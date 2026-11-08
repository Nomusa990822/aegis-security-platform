import argparse
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.database import DATABASE_PATH
from app.response.audit_checkpoint import (
    checkpoint_lock,
    checkpoint_path,
    load_checkpoint_configuration,
)
from app.response.checkpoint_intent import (
    checkpoint_intent_path,
    verify_checkpoint_intent,
)


def _database_references_response(
    connection: sqlite3.Connection,
    response_id: int,
) -> dict[str, bool]:
    record = connection.execute(
        "SELECT 1 FROM response_records WHERE id = ? LIMIT 1",
        (response_id,),
    ).fetchone()
    head = connection.execute(
        "SELECT 1 FROM response_audit_chain_heads WHERE response_id = ? LIMIT 1",
        (response_id,),
    ).fetchone()
    event = connection.execute(
        "SELECT 1 FROM response_audit_log WHERE response_id = ? LIMIT 1",
        (response_id,),
    ).fetchone()
    return {
        "record": record is not None,
        "chain_head": head is not None,
        "audit_events": event is not None,
    }


def _write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    temporary_path = None
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f"{path.stem}_",
        suffix=".tmp",
        delete=False,
    ) as temporary_file:
        temporary_path = Path(temporary_file.name)
        json.dump(
            manifest,
            temporary_file,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        temporary_file.write("\n")
        temporary_file.flush()
        os.fsync(temporary_file.fileno())

    try:
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
        os.chmod(path, 0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def _fsync_directory(path: Path) -> None:
    directory_fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def quarantine_stale_checkpoint_intents(
    connection: sqlite3.Connection,
    checkpoint_directory: Path,
    *,
    apply: bool = False,
    response_ids: set[int] | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    """Inspect stale intents, or preserve proven orphan intents as evidence."""
    checkpoint_directory = Path(checkpoint_directory).resolve()
    configured_directory = Path(load_checkpoint_configuration()[4]).resolve()
    if checkpoint_directory != configured_directory:
        raise ValueError(
            "Quarantine directory does not match AEGIS_AUDIT_CHECKPOINT_DIR."
        )
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
    if apply and (not isinstance(reason, str) or not reason.strip()):
        raise ValueError("A non-empty --reason is required when applying quarantine.")

    quarantine_directory = checkpoint_directory / "quarantine"
    if quarantine_directory.is_symlink():
        raise ValueError("Quarantine directory must not be a symbolic link.")
    discovered: set[int] = set()
    if checkpoint_directory.exists():
        if not checkpoint_directory.is_dir():
            raise ValueError("Checkpoint path is not a directory.")
        for path in checkpoint_directory.iterdir():
            if path.is_file() and path.name.endswith(".pending.json"):
                prefix = path.name.removeprefix("response_").removesuffix(".pending.json")
                if prefix.isdigit() and int(prefix) > 0:
                    discovered.add(int(prefix))

    selected = sorted(discovered if response_ids is None else response_ids)
    report: dict[str, Any] = {
        "mode": "apply" if apply else "dry_run",
        "database": "read_only_connection",
        "checkpoint_directory": str(checkpoint_directory),
        "quarantine_directory": str(quarantine_directory),
        "selected_response_ids": selected,
        "eligible_response_ids": [],
        "quarantined_response_ids": [],
        "skipped": [],
        "errors": [],
    }

    for response_id in selected:
        intent_path = checkpoint_intent_path(checkpoint_directory, response_id)
        checkpoint_file = checkpoint_path(checkpoint_directory, response_id)
        if intent_path.is_symlink():
            report["skipped"].append({
                "response_id": response_id,
                "classification": "intent_is_symlink",
                "reasons": ["Symbolic-link intents are not eligible for quarantine."],
            })
            continue
        if not intent_path.is_file():
            report["skipped"].append({
                "response_id": response_id,
                "classification": "intent_missing",
                "reasons": ["Pending intent file does not exist."],
            })
            continue

        verification = verify_checkpoint_intent(response_id)
        if not verification["valid"]:
            report["skipped"].append({
                "response_id": response_id,
                "classification": "intent_corrupt_or_unverifiable",
                "reasons": verification["errors"],
            })
            continue

        references = _database_references_response(connection, response_id)
        if any(references.values()):
            report["skipped"].append({
                "response_id": response_id,
                "classification": "database_reference_exists",
                "database_references": references,
                "reasons": [
                    "A response record, chain head, or audit event exists; "
                    "preserve the intent for manual investigation or normal recovery."
                ],
            })
            continue

        if os.path.lexists(checkpoint_file):
            report["skipped"].append({
                "response_id": response_id,
                "classification": "checkpoint_exists",
                "reasons": [
                    "A checkpoint already exists; use inventory and recovery "
                    "to determine whether it is valid."
                ],
            })
            continue

        report["eligible_response_ids"].append(response_id)
        if not apply:
            continue

        try:
            quarantine_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            if quarantine_directory.is_symlink() or not quarantine_directory.is_dir():
                raise RuntimeError("Quarantine destination is not a regular directory.")
            os.chmod(quarantine_directory, 0o700)
            with checkpoint_lock(checkpoint_directory, response_id):
                # Recheck the evidence under the same per-response lock used by
                # intent creation and checkpoint publication.
                current_bytes = intent_path.read_bytes()
                current_hash = hashlib.sha256(current_bytes).hexdigest()
                current_verification = verify_checkpoint_intent(response_id)
                current_references = _database_references_response(
                    connection,
                    response_id,
                )
                if not current_verification["valid"]:
                    raise RuntimeError(
                        "Intent became invalid during quarantine: "
                        + "; ".join(current_verification["errors"])
                    )
                if any(current_references.values()):
                    raise RuntimeError(
                        "Database references appeared during quarantine."
                    )
                if os.path.lexists(checkpoint_file):
                    raise RuntimeError(
                        "A checkpoint appeared during quarantine."
                    )

                evidence_name = (
                    f"response_{response_id}_{current_hash}.pending.json"
                )
                evidence_path = quarantine_directory / evidence_name
                manifest_path = quarantine_directory / (
                    f"response_{response_id}_{current_hash}.manifest.json"
                )
                if os.path.lexists(evidence_path) or os.path.lexists(manifest_path):
                    raise RuntimeError(
                        "Quarantine evidence destination already exists; "
                        "refusing to overwrite evidence."
                    )

                # Ensure the bytes being moved are exactly the signed document
                # that was verified above.
                if hashlib.sha256(intent_path.read_bytes()).hexdigest() != current_hash:
                    raise RuntimeError("Intent changed while quarantine was prepared.")

                os.replace(intent_path, evidence_path)
                os.chmod(evidence_path, 0o600)
                _fsync_directory(checkpoint_directory)
                _fsync_directory(quarantine_directory)

                manifest = {
                    "manifest_schema_version": 1,
                    "response_id": response_id,
                    "original_filename": intent_path.name,
                    "quarantined_filename": evidence_name,
                    "sha256": current_hash,
                    "quarantined_at": datetime.now(timezone.utc).isoformat(),
                    "reason": reason.strip(),
                    "intent_payload": current_verification["intent"],
                    "database_references_at_quarantine": current_references,
                    "checkpoint_present_at_quarantine": False,
                }
                _write_manifest(manifest_path, manifest)
                report["quarantined_response_ids"].append(response_id)
                report.setdefault("evidence", []).append({
                    "response_id": response_id,
                    "intent_file": str(evidence_path),
                    "manifest_file": str(manifest_path),
                    "sha256": current_hash,
                })
        except (OSError, RuntimeError, ValueError) as exc:
            report["errors"].append({
                "response_id": response_id,
                "error": str(exc),
            })

    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Quarantine only signed checkpoint intents with no corresponding "
            "database or checkpoint artifacts. Defaults to dry-run."
        )
    )
    parser.add_argument("--database", type=Path, default=DATABASE_PATH)
    parser.add_argument(
        "--response-id",
        type=int,
        action="append",
        dest="response_ids",
        help="Limit operation to this response ID; may be repeated.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Move eligible signed intents into the evidence quarantine.",
    )
    parser.add_argument(
        "--reason",
        help="Required operator-supplied reason when --apply is used.",
    )
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
            report = quarantine_stale_checkpoint_intents(
                connection,
                checkpoint_directory,
                apply=args.apply,
                response_ids=(
                    set(args.response_ids)
                    if args.response_ids is not None
                    else None
                ),
                reason=args.reason,
            )
        finally:
            connection.close()

        print(json.dumps(report, indent=2, sort_keys=True))
        if report["errors"] or (args.apply and report["skipped"]):
            return 1
        return 0
    except (OSError, ValueError, sqlite3.Error, RuntimeError) as exc:
        print(f"Checkpoint intent quarantine failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
