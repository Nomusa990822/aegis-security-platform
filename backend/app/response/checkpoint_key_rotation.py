import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from app.response.audit_checkpoint import (
    KEY_ID_PATTERN,
    load_checkpoint_configuration,
    reject_duplicate_json_keys,
)
from app.response.checkpoint_key_usage import (
    CHECKPOINT_PATTERN,
    INTENT_PATTERN,
    QUARANTINED_INTENT_PATTERN,
    _inspect_signed_document,
)


def _validate_secret(value: Any, name: str) -> bytes:
    if not isinstance(value, str) or len(value) < 32:
        raise ValueError(f"{name} must contain at least 32 characters.")
    return value.encode("utf-8")


def validate_proposed_checkpoint_configuration(
    checkpoint_directory: Path,
    *,
    active_secret: str,
    active_key_id: str,
    previous_keys: dict[str, str],
    legacy_secret: str,
) -> dict[str, Any]:
    """Check whether a proposed key configuration verifies all local evidence."""
    if not isinstance(active_key_id, str) or not KEY_ID_PATTERN.fullmatch(active_key_id):
        raise ValueError("Proposed active key ID is invalid.")

    active_secret_bytes = _validate_secret(
        active_secret,
        "Proposed active checkpoint key",
    )
    legacy_secret_bytes = _validate_secret(
        legacy_secret,
        "Proposed legacy checkpoint key",
    )

    if not isinstance(previous_keys, dict):
        raise ValueError("Proposed previous keys must be a JSON object.")

    proposed_keyring: dict[str, bytes] = {}
    for key_id, secret in previous_keys.items():
        if not isinstance(key_id, str) or not KEY_ID_PATTERN.fullmatch(key_id):
            raise ValueError("A proposed previous key ID is invalid.")
        if key_id == active_key_id:
            raise ValueError("The active key ID cannot also be a previous key.")
        proposed_keyring[key_id] = _validate_secret(
            secret,
            f"Proposed previous checkpoint key {key_id!r}",
        )
    proposed_keyring[active_key_id] = active_secret_bytes

    checkpoint_directory = Path(checkpoint_directory).expanduser()
    if checkpoint_directory.is_symlink():
        raise ValueError("Checkpoint directory must not be a symbolic link.")
    checkpoint_directory = checkpoint_directory.resolve()
    configured_directory = Path(load_checkpoint_configuration()[4]).resolve()
    if checkpoint_directory != configured_directory:
        raise ValueError(
            "Preflight directory must match AEGIS_AUDIT_CHECKPOINT_DIR."
        )

    inspected: list[dict[str, Any]] = []
    filesystem_errors: list[dict[str, str]] = []

    if checkpoint_directory.exists():
        if not checkpoint_directory.is_dir():
            raise ValueError("Checkpoint directory must be a regular directory.")

        for path in sorted(checkpoint_directory.iterdir()):
            if path.name == "quarantine":
                if path.is_symlink() or not path.is_dir():
                    filesystem_errors.append({
                        "file": str(path),
                        "error": "Quarantine path is not a regular directory.",
                    })
                    continue
                for candidate in sorted(path.iterdir()):
                    if not QUARANTINED_INTENT_PATTERN.fullmatch(candidate.name):
                        continue
                    if candidate.is_symlink() or not candidate.is_file():
                        filesystem_errors.append({
                            "file": str(candidate),
                            "error": "Quarantined intent is not a regular file.",
                        })
                        continue
                    inspected.append(
                        _inspect_signed_document(
                            candidate,
                            document_type="quarantined_intent",
                            keyring=proposed_keyring,
                            legacy_secret=legacy_secret_bytes,
                        )
                    )
                continue

            if not (
                CHECKPOINT_PATTERN.fullmatch(path.name)
                or INTENT_PATTERN.fullmatch(path.name)
            ):
                continue
            if path.is_symlink() or not path.is_file():
                filesystem_errors.append({
                    "file": str(path),
                    "error": "Signed document path is not a regular file.",
                })
                continue
            inspected.append(
                _inspect_signed_document(
                    path,
                    document_type=(
                        "checkpoint"
                        if CHECKPOINT_PATTERN.fullmatch(path.name)
                        else "pending_intent"
                    ),
                    keyring=proposed_keyring,
                    legacy_secret=legacy_secret_bytes,
                )
            )

    failures = [
        item for item in inspected
        if not item.get("signature_valid", False)
    ]
    passed = not failures and not filesystem_errors

    return {
        "valid": passed,
        "proposed_active_key_id": active_key_id,
        "proposed_previous_key_ids": sorted(previous_keys),
        "documents_inspected": len(inspected),
        "documents_verified": len(inspected) - len(failures),
        "verification_failures": failures,
        "filesystem_errors": filesystem_errors,
        "recommendation": (
            "Configuration can verify all inspected local evidence. "
            "Check backups and archived copies before rotation."
            if passed
            else "Do not activate this configuration. Retain or restore the "
            "required signing keys and rerun preflight."
        ),
        "scope_note": (
            "This is a read-only local evidence check. It does not update "
            "environment variables, rotate keys, or inspect external backups."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only preflight for a proposed AEGIS checkpoint signing-key "
            "configuration. Proposed secrets are read from environment variables."
        )
    )
    parser.add_argument(
        "--directory",
        type=Path,
        help="Optional directory; must match AEGIS_AUDIT_CHECKPOINT_DIR.",
    )
    args = parser.parse_args(argv)

    try:
        configured_directory = load_checkpoint_configuration()[4]
        proposed_active_secret = os.getenv(
            "AEGIS_AUDIT_CHECKPOINT_NEXT_KEY", ""
        )
        proposed_active_key_id = os.getenv(
            "AEGIS_AUDIT_CHECKPOINT_NEXT_KEY_ID", ""
        )
        proposed_previous_raw = os.getenv(
            "AEGIS_AUDIT_CHECKPOINT_NEXT_PREVIOUS_KEYS", "{}"
        )
        proposed_legacy_secret = os.getenv(
            "AEGIS_AUDIT_CHECKPOINT_NEXT_LEGACY_KEY",
            os.getenv("AEGIS_AUDIT_CHECKPOINT_LEGACY_KEY", ""),
        )

        proposed_previous_keys = json.loads(
            proposed_previous_raw,
            object_pairs_hook=reject_duplicate_json_keys,
        )

        report = validate_proposed_checkpoint_configuration(
            args.directory or configured_directory,
            active_secret=proposed_active_secret,
            active_key_id=proposed_active_key_id,
            previous_keys=proposed_previous_keys,
            legacy_secret=proposed_legacy_secret,
        )
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["valid"] else 1

    except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
        print(
            f"Checkpoint key-rotation preflight failed: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
