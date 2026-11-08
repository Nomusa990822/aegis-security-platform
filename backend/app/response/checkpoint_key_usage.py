import argparse
import hmac
import json
import re
import sys
from pathlib import Path
from typing import Any

from app.response.audit_checkpoint import (
    CHECKPOINT_SCHEMA_VERSION,
    LEGACY_CHECKPOINT_SCHEMA_VERSION,
    load_checkpoint_configuration,
    reject_duplicate_json_keys,
    sign_checkpoint,
)


CHECKPOINT_PATTERN = re.compile(r"^response_([1-9][0-9]*)\.json$")
INTENT_PATTERN = re.compile(r"^response_([1-9][0-9]*)\.pending\.json$")


def _inspect_signed_document(
    path: Path,
    *,
    document_type: str,
    keyring: dict[str, bytes],
    legacy_secret: bytes,
) -> dict[str, Any]:
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_json_keys,
        )
        if not isinstance(document, dict):
            raise ValueError("Signed document must be a JSON object.")

        payload = document.get("payload")
        signature = document.get("signature")
        if not isinstance(payload, dict) or not isinstance(signature, str):
            raise ValueError("Signed document payload or signature is invalid.")

        if document_type == "checkpoint":
            schema_version = payload.get("schema_version")
            if schema_version == LEGACY_CHECKPOINT_SCHEMA_VERSION:
                key_id = "__legacy__"
                secret = legacy_secret
            elif schema_version == CHECKPOINT_SCHEMA_VERSION:
                key_id = payload.get("key_id")
                if not isinstance(key_id, str) or not key_id:
                    raise ValueError("Checkpoint key ID is missing or invalid.")
                secret = keyring.get(key_id)
            else:
                raise ValueError("Unsupported checkpoint schema version.")
        else:
            schema_version = payload.get("intent_schema_version")
            if schema_version != 1:
                raise ValueError("Unsupported checkpoint intent schema version.")
            key_id = payload.get("key_id")
            if not isinstance(key_id, str) or not key_id:
                raise ValueError("Checkpoint intent key ID is missing or invalid.")
            secret = keyring.get(key_id)

        key_available = secret is not None
        signature_valid = False
        if secret is not None:
            expected = sign_checkpoint(payload, secret)
            signature_valid = hmac.compare_digest(signature, expected)

        return {
            "file": str(path),
            "document_type": document_type,
            "schema_version": schema_version,
            "key_id": key_id,
            "key_available": key_available,
            "signature_valid": signature_valid,
        }
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        return {
            "file": str(path),
            "document_type": document_type,
            "key_id": None,
            "key_available": False,
            "signature_valid": False,
            "error": str(exc),
        }


def inspect_checkpoint_key_usage(
    checkpoint_directory: Path,
) -> dict[str, Any]:
    """Inventory signing-key references without exposing key material."""
    (
        _active_secret,
        active_key_id,
        keyring,
        legacy_secret,
        configured_directory,
    ) = load_checkpoint_configuration()

    checkpoint_directory = Path(checkpoint_directory).resolve()
    if checkpoint_directory != Path(configured_directory).resolve():
        raise ValueError(
            "Key-usage inventory directory does not match "
            "AEGIS_AUDIT_CHECKPOINT_DIR."
        )

    documents: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    if checkpoint_directory.exists():
        if checkpoint_directory.is_symlink() or not checkpoint_directory.is_dir():
            raise ValueError("Checkpoint directory must be a regular directory.")

        for path in sorted(checkpoint_directory.iterdir()):
            if path.name == "quarantine":
                if path.is_symlink() or not path.is_dir():
                    errors.append({
                        "file": str(path),
                        "error": "Quarantine path is not a regular directory.",
                    })
                    continue
                candidates = sorted(path.iterdir())
                for candidate in candidates:
                    if INTENT_PATTERN.fullmatch(candidate.name):
                        if candidate.is_symlink() or not candidate.is_file():
                            errors.append({
                                "file": str(candidate),
                                "error": "Quarantined intent is not a regular file.",
                            })
                            continue
                        documents.append(
                            _inspect_signed_document(
                                candidate,
                                document_type="quarantined_intent",
                                keyring=keyring,
                                legacy_secret=legacy_secret,
                            )
                        )
                continue

            checkpoint_match = CHECKPOINT_PATTERN.fullmatch(path.name)
            intent_match = INTENT_PATTERN.fullmatch(path.name)
            if not checkpoint_match and not intent_match:
                continue
            if path.is_symlink() or not path.is_file():
                errors.append({
                    "file": str(path),
                    "error": "Signed document path is not a regular file.",
                })
                continue

            documents.append(
                _inspect_signed_document(
                    path,
                    document_type=(
                        "checkpoint" if checkpoint_match else "pending_intent"
                    ),
                    keyring=keyring,
                    legacy_secret=legacy_secret,
                )
            )

    usage: dict[str, list[dict[str, str]]] = {}
    for document in documents:
        key_id = document.get("key_id")
        if isinstance(key_id, str):
            usage.setdefault(key_id, []).append({
                "file": document["file"],
                "document_type": document["document_type"],
            })

    configured_key_ids = sorted(keyring)
    referenced_key_ids = sorted(usage)
    missing_key_ids = sorted(
        key_id
        for key_id in referenced_key_ids
        if key_id != "__legacy__" and key_id not in keyring
    )
    invalid_documents = [
        document
        for document in documents
        if not document.get("signature_valid", False)
    ]
    legacy_references = usage.get("__legacy__", [])
    configured_non_active = sorted(
        key_id for key_id in keyring if key_id != active_key_id
    )
    safe_to_retire = [
        key_id
        for key_id in configured_non_active
        if key_id not in usage
    ]

    # Unknown or invalid signed documents make a clean retirement decision
    # impossible: their actual key dependencies cannot be trusted.
    retirement_assessment = (
        "blocked"
        if errors or invalid_documents or missing_key_ids
        else "review_required"
    )

    return {
        "checkpoint_directory": str(checkpoint_directory),
        "active_key_id": active_key_id,
        "configured_key_ids": configured_key_ids,
        "referenced_key_ids": referenced_key_ids,
        "key_usage": usage,
        "missing_key_ids": missing_key_ids,
        "legacy_key_references": len(legacy_references),
        "documents_inspected": len(documents),
        "invalid_or_unverifiable_documents": invalid_documents,
        "filesystem_errors": errors,
        "configured_non_active_keys_without_references": safe_to_retire,
        "retirement_assessment": retirement_assessment,
        "retirement_note": (
            "A key with zero references in this inventory may still be needed "
            "for backups or external copies. Confirm retention and backup "
            "coverage before removing any key. This report never changes keys."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Inventory checkpoint signing-key usage. No secrets are printed "
            "and no files or environment settings are changed."
        )
    )
    parser.add_argument(
        "--directory",
        type=Path,
        help="Optional checkpoint directory; must match configured directory.",
    )
    args = parser.parse_args(argv)

    try:
        configured_directory = load_checkpoint_configuration()[4]
        report = inspect_checkpoint_key_usage(
            args.directory or configured_directory
        )
        print(json.dumps(report, indent=2, sort_keys=True))
        if (
            report["filesystem_errors"]
            or report["invalid_or_unverifiable_documents"]
            or report["missing_key_ids"]
        ):
            return 1
        return 0
    except (OSError, ValueError) as exc:
        print(f"Checkpoint key-usage inventory failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
