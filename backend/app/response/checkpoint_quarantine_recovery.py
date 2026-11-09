import argparse
import hashlib
import hmac
import json
import os
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any

from app.database import DATABASE_PATH
from app.response.audit_checkpoint import (
    checkpoint_lock,
    checkpoint_path,
    load_checkpoint_configuration,
    reject_duplicate_json_keys,
    sign_checkpoint,
)
from app.response.checkpoint_intent import checkpoint_intent_path
from app.response.checkpoint_intent_quarantine import (
    _database_references_response,
    _fsync_directory,
    _write_manifest,
)


MANIFEST_PATTERN = re.compile(
    r"^response_([1-9][0-9]*)_([0-9a-f]{64})\.manifest\.json$"
)
EVIDENCE_PATTERN = re.compile(
    r"^response_([1-9][0-9]*)_([0-9a-f]{64})\.pending\.json$"
)
MANIFEST_TEMP_PATTERN = re.compile(
    r"^response_([1-9][0-9]*)_[0-9a-f]{64}\.manifest_.*\.tmp$"
)


def _read_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_json_keys,
    )
    if not isinstance(value, dict):
        raise ValueError("JSON document must be an object.")
    return value


def _verify_signed_intent_bytes(
    raw: bytes,
    *,
    response_id: int,
    expected_payload: dict[str, Any],
    keyring: dict[str, bytes],
) -> tuple[bool, str | None]:
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate_json_keys,
        )
        if not isinstance(document, dict):
            raise ValueError("Signed intent must be a JSON object.")
        payload = document.get("payload")
        signature = document.get("signature")
        if not isinstance(payload, dict) or not isinstance(signature, str):
            raise ValueError("Signed intent payload or signature is invalid.")
        if payload != expected_payload:
            raise ValueError("Manifest payload does not match signed intent payload.")
        if payload.get("response_id") != response_id:
            raise ValueError("Signed intent response ID does not match manifest.")
        if payload.get("intent_schema_version") != 1:
            raise ValueError("Unsupported signed intent schema version.")
        if (
            payload.get("event_count") != 1
            or payload.get("previous_event_count") != 0
            or payload.get("previous_final_hash") != "0" * 64
        ):
            raise ValueError("Quarantined intent is not an initial orphan intent.")
        key_id = payload.get("key_id")
        if not isinstance(key_id, str) or key_id not in keyring:
            raise ValueError("Signing key is unavailable for quarantined intent.")
        expected_signature = sign_checkpoint(payload, keyring[key_id])
        if not hmac.compare_digest(signature, expected_signature):
            raise ValueError("Quarantined intent signature is invalid.")
        return True, None
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        TypeError,
    ) as exc:
        return False, str(exc)


def _manifest_paths(
    quarantine_directory: Path,
    response_id: int,
    digest: str,
) -> tuple[Path, Path]:
    stem = f"response_{response_id}_{digest}"
    return (
        quarantine_directory / f"{stem}.pending.json",
        quarantine_directory / f"{stem}.manifest.json",
    )


def recover_quarantine_manifests(
    connection: sqlite3.Connection,
    checkpoint_directory: Path,
    *,
    apply: bool = False,
    response_ids: set[int] | None = None,
) -> dict[str, Any]:
    """Inspect or finish interrupted two-stage quarantine manifest operations.

    The database connection must be read-only. This function never deletes
    evidence, invents manifests, or overwrites an existing evidence file.
    """
    supplied_directory = Path(checkpoint_directory).expanduser()
    if supplied_directory.is_symlink():
        raise ValueError("Checkpoint directory must not be a symbolic link.")
    checkpoint_directory = supplied_directory.resolve()
    (
        _active_secret,
        _active_key_id,
        keyring,
        _legacy_secret,
        configured_directory,
    ) = load_checkpoint_configuration()
    if checkpoint_directory != Path(configured_directory).resolve():
        raise ValueError("Quarantine recovery directory does not match configured directory.")

    quarantine_directory = checkpoint_directory / "quarantine"
    if quarantine_directory.is_symlink():
        raise ValueError("Quarantine directory must not be a symbolic link.")
    if not quarantine_directory.exists():
        return {
            "mode": "apply" if apply else "dry_run",
            "database": "read_only_connection",
            "manifest_results": [],
            "orphan_evidence": [],
            "temporary_artifacts": [],
            "errors": [],
        }
    if not quarantine_directory.is_dir():
        raise ValueError("Quarantine path is not a regular directory.")

    manifests: dict[tuple[int, str], Path] = {}
    evidence: dict[tuple[int, str], Path] = {}
    temporary_artifacts: list[dict[str, Any]] = []
    unrecognized: list[str] = []

    for path in sorted(quarantine_directory.iterdir()):
        if path.is_symlink():
            unrecognized.append(path.name)
            continue
        manifest_match = MANIFEST_PATTERN.fullmatch(path.name)
        evidence_match = EVIDENCE_PATTERN.fullmatch(path.name)
        temp_match = MANIFEST_TEMP_PATTERN.fullmatch(path.name)
        if manifest_match and path.is_file():
            key = (int(manifest_match.group(1)), manifest_match.group(2))
            if key in manifests:
                unrecognized.append(path.name)
            else:
                manifests[key] = path
        elif evidence_match and path.is_file():
            key = (int(evidence_match.group(1)), evidence_match.group(2))
            if key in evidence:
                unrecognized.append(path.name)
            else:
                evidence[key] = path
        elif temp_match and path.is_file():
            temporary_artifacts.append({
                "file": str(path),
                "response_id": int(temp_match.group(1)),
                "classification": "unverified_manifest_temporary_file_preserved",
            })
        else:
            unrecognized.append(path.name)

    if response_ids is not None and (
        not response_ids
        or any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 1
            for value in response_ids
        )
    ):
        raise ValueError("Selected response IDs must be positive integers.")
    if apply and response_ids is None:
        raise ValueError("Apply requires at least one explicit --response-id.")

    selected = set(response_ids) if response_ids is not None else None
    results: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    referenced_evidence: set[tuple[int, str]] = set()

    for key, manifest_path in sorted(manifests.items()):
        response_id, digest = key
        if selected is not None and response_id not in selected:
            continue
        evidence_path, _ = _manifest_paths(quarantine_directory, response_id, digest)
        source_path = checkpoint_intent_path(checkpoint_directory, response_id)
        checkpoint_file = checkpoint_path(checkpoint_directory, response_id)
        item: dict[str, Any] = {
            "response_id": response_id,
            "sha256": digest,
            "manifest_file": str(manifest_path),
            "evidence_file": str(evidence_path),
            "classification": "unverified",
            "recovery_eligible": False,
            "recovered": False,
            "errors": [],
        }
        referenced_evidence.add(key)

        try:
            manifest = _read_json_object(manifest_path)
            if manifest.get("response_id") != response_id:
                raise ValueError("Manifest response ID does not match its filename.")
            if manifest.get("sha256") != digest:
                raise ValueError("Manifest digest does not match its filename.")
            if manifest.get("quarantined_filename") != evidence_path.name:
                raise ValueError("Manifest evidence filename does not match its pair.")
            if manifest.get("original_filename") != source_path.name:
                raise ValueError("Manifest original filename is invalid.")
            payload = manifest.get("intent_payload")
            if not isinstance(payload, dict):
                raise ValueError("Manifest signed intent payload is missing.")
            reason = manifest.get("reason")
            if not isinstance(reason, str) or not reason.strip():
                raise ValueError("Manifest operator reason is missing.")
            database_snapshot = manifest.get("database_references_at_quarantine")
            if not isinstance(database_snapshot, dict) or any(
                database_snapshot.get(field) is not False
                for field in ("record", "chain_head", "audit_events")
            ):
                raise ValueError("Manifest does not prove an unreferenced database state.")
            if manifest.get("checkpoint_present_at_quarantine") is not False:
                raise ValueError("Manifest does not prove checkpoint absence.")

            schema_version = manifest.get("manifest_schema_version")
            state = manifest.get("status")
            if schema_version == 1:
                # Historical manifests were written only after the move.
                state = "completed"
            elif schema_version != 2 or state not in {"prepared", "completed"}:
                raise ValueError("Unsupported quarantine manifest schema or status.")
            elif not isinstance(manifest.get("prepared_at"), str) or not manifest["prepared_at"].strip():
                raise ValueError("Prepared manifest timestamp is missing.")

            evidence_exists = os.path.lexists(evidence_path)
            source_exists = os.path.lexists(source_path)
            if evidence_exists and evidence_path.is_symlink():
                raise ValueError("Quarantined evidence is a symbolic link.")
            if source_exists and source_path.is_symlink():
                raise ValueError("Original pending intent is a symbolic link.")
            if evidence_exists and not evidence_path.is_file():
                raise ValueError("Quarantined evidence is not a regular file.")
            if source_exists and not source_path.is_file():
                raise ValueError("Original pending intent is not a regular file.")

            candidate_path = evidence_path if evidence_exists else source_path if source_exists else None
            if candidate_path is None:
                item["classification"] = "manifest_without_intent_evidence"
                item["errors"].append("Neither quarantined evidence nor original pending intent exists.")
            else:
                raw = candidate_path.read_bytes()
                actual_digest = hashlib.sha256(raw).hexdigest()
                if actual_digest != digest:
                    raise ValueError("Intent bytes do not match the manifest SHA-256.")
                valid, signature_error = _verify_signed_intent_bytes(
                    raw,
                    response_id=response_id,
                    expected_payload=payload,
                    keyring=keyring,
                )
                if not valid:
                    raise ValueError(signature_error or "Signed intent verification failed.")

                if evidence_exists and source_exists:
                    item["classification"] = "ambiguous_source_and_evidence_both_exist"
                    item["errors"].append("Both source intent and quarantine evidence exist; preserve both for manual review.")
                elif state == "completed" and evidence_exists:
                    item["classification"] = "completed_pair_valid"
                elif state == "completed" and source_exists:
                    item["classification"] = "completed_manifest_source_still_present"
                    item["errors"].append("Manifest says completed but evidence is still at the original path.")
                elif state == "prepared":
                    references = _database_references_response(connection, response_id)
                    if any(references.values()):
                        item["classification"] = "prepared_but_database_referenced"
                        item["errors"].append("Database references now exist; automatic quarantine recovery is refused.")
                    elif os.path.lexists(checkpoint_file):
                        item["classification"] = "prepared_but_checkpoint_exists"
                        item["errors"].append("A checkpoint now exists; automatic quarantine recovery is refused.")
                    else:
                        item["classification"] = (
                            "prepared_evidence_moved_manifest_pending"
                            if evidence_exists
                            else "prepared_manifest_move_pending"
                        )
                        item["recovery_eligible"] = True

            if apply and item["recovery_eligible"]:
                quarantine_directory_check = quarantine_directory
                if quarantine_directory_check.is_symlink() or not quarantine_directory_check.is_dir():
                    raise ValueError("Quarantine directory changed or is not a regular directory.")
                with checkpoint_lock(checkpoint_directory, response_id):
                    # Re-read all state while holding the same per-response lock.
                    current_manifest = _read_json_object(manifest_path)
                    if current_manifest != manifest:
                        raise ValueError("Manifest changed after inspection; refusing recovery.")
                    current_source_exists = os.path.lexists(source_path)
                    current_evidence_exists = os.path.lexists(evidence_path)
                    if source_path.is_symlink() or evidence_path.is_symlink():
                        raise ValueError("Source or evidence path became a symbolic link.")
                    if current_source_exists and current_evidence_exists:
                        raise ValueError("Source and evidence both exist; refusing ambiguous recovery.")
                    references = _database_references_response(connection, response_id)
                    if any(references.values()) or os.path.lexists(checkpoint_file):
                        raise ValueError("Database reference or checkpoint appeared before recovery.")
                    current_path = evidence_path if current_evidence_exists else source_path
                    if not current_path.is_file():
                        raise ValueError("Prepared intent bytes are missing.")
                    current_bytes = current_path.read_bytes()
                    current_digest = hashlib.sha256(current_bytes).hexdigest()
                    if current_digest != digest:
                        raise ValueError("Prepared intent changed before recovery.")
                    valid, signature_error = _verify_signed_intent_bytes(
                        current_bytes,
                        response_id=response_id,
                        expected_payload=current_manifest["intent_payload"],
                        keyring=keyring,
                    )
                    if not valid:
                        raise ValueError(signature_error or "Prepared intent signature is invalid.")
                    if current_path == source_path:
                        if os.path.lexists(evidence_path):
                            raise ValueError("Evidence destination already exists.")
                        os.replace(source_path, evidence_path)
                        os.chmod(evidence_path, 0o600)
                        _fsync_directory(checkpoint_directory)
                        _fsync_directory(quarantine_directory)
                    completed = dict(current_manifest)
                    completed["status"] = "completed"
                    completed["quarantined_at"] = completed.get("quarantined_at") or completed.get("prepared_at")
                    _write_manifest(manifest_path, completed)
                    item["classification"] = "recovered_completed"
                    item["recovery_eligible"] = False
                    item["recovered"] = True
        except (OSError, ValueError, TypeError, KeyError, RuntimeError) as exc:
            item["classification"] = "recovery_error_preserved"
            item["errors"].append(str(exc))
            errors.append({"response_id": response_id, "error": str(exc)})

        results.append(item)

    orphan_evidence = []
    for key, evidence_path in sorted(evidence.items()):
        if selected is not None and key[0] not in selected:
            continue
        if key not in referenced_evidence:
            orphan_evidence.append({
                "response_id": key[0],
                "file": str(evidence_path),
                "classification": "evidence_without_manifest_preserved",
            })

    return {
        "mode": "apply" if apply else "dry_run",
        "database": "read_only_connection",
        "checkpoint_directory": str(checkpoint_directory),
        "quarantine_directory": str(quarantine_directory),
        "manifest_results": results,
        "orphan_evidence": orphan_evidence,
        "temporary_artifacts": temporary_artifacts,
        "unrecognized_files": unrecognized,
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Inspect or recover interrupted quarantine manifest operations. "
            "Defaults to read-only dry-run."
        )
    )
    parser.add_argument("--database", type=Path, default=DATABASE_PATH)
    parser.add_argument("--response-id", type=int, action="append", dest="response_ids")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)

    database_path = args.database.resolve()
    if not database_path.is_file():
        print(f"Database file does not exist: {database_path}", file=sys.stderr)
        return 2
    try:
        checkpoint_directory = Path(load_checkpoint_configuration()[4])
        connection = sqlite3.connect(
            f"{database_path.as_uri()}?mode=ro",
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only = ON")
            report = recover_quarantine_manifests(
                connection,
                checkpoint_directory,
                apply=args.apply,
                response_ids=set(args.response_ids) if args.response_ids is not None else None,
            )
        finally:
            connection.close()
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1 if report["errors"] else 0
    except (OSError, ValueError, sqlite3.Error, RuntimeError) as exc:
        print(f"Quarantine recovery failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
