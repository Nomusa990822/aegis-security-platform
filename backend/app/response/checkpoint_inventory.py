
import argparse
import json
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.database import DATABASE_PATH
from app.response.audit import validate_response_audit
from app.response.audit_chain import verify_hash_chain
from app.response.audit_checkpoint import (
    checkpoint_path,
    load_checkpoint_configuration,
    verify_audit_checkpoint,
)
from app.response.repository import get_response_record


CHECKPOINT_FILENAME_PATTERN = re.compile(
    r"^response_([1-9][0-9]*)\.json$"
)

TEMPORARY_FILENAME_PATTERN = re.compile(
    r"^response_([1-9][0-9]*)_.*\.tmp$"
)

LOCK_FILENAME_PATTERN = re.compile(
    r"^response_([1-9][0-9]*)\.lock$"
)

PENDING_INTENT_FILENAME_PATTERN = re.compile(
    r"^response_([1-9][0-9]*)\.pending\.json$"
)


def _read_checkpoint_metadata(path: Path) -> dict[str, Any]:
    """Read checkpoint metadata without treating it as verified evidence."""
    try:
        with path.open("r", encoding="utf-8") as checkpoint_file:
            document = json.load(checkpoint_file)

        if not isinstance(document, dict):
            return {
                "readable": False,
                "schema_version": None,
                "key_id": None,
                "error": "Checkpoint document must be a JSON object.",
            }

        payload = document.get("payload")

        if not isinstance(payload, dict):
            return {
                "readable": False,
                "schema_version": None,
                "key_id": None,
                "error": "Checkpoint payload must be a JSON object.",
            }

        return {
            "readable": True,
            "schema_version": payload.get("schema_version"),
            "key_id": payload.get("key_id"),
            "error": None,
        }

    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return {
            "readable": False,
            "schema_version": None,
            "key_id": None,
            "error": f"Unable to read checkpoint document: {exc}",
        }


def _load_audit_events(
    connection: sqlite3.Connection,
    response_id: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Load audit events and parse their JSON details."""
    rows = connection.execute(
        """
        SELECT *
        FROM response_audit_log
        WHERE response_id = ?
        ORDER BY id ASC
        """,
        (response_id,),
    ).fetchall()

    events = []
    errors = []

    for row in rows:
        event = dict(row)

        try:
            event["details"] = json.loads(event["details"])
        except (json.JSONDecodeError, TypeError) as exc:
            errors.append(
                f"Audit event {event.get('id')} has invalid JSON details: {exc}"
            )

        events.append(event)

    return events, errors


def _inspect_response(
    connection: sqlite3.Connection,
    response_id: int,
    checkpoint_directory: Path,
    active_key_id: str,
    keyring: dict[str, str],
) -> dict[str, Any]:
    """Inspect one response record without modifying database or files."""
    result = {
        "response_id": response_id,
        "record_exists": False,
        "chain_head_exists": False,
        "event_count": 0,
        "calculated_event_count": None,
        "final_hash": None,
        "calculated_final_hash": None,
        "lifecycle_valid": None,
        "hash_chain_valid": None,
        "chain_head_matches": None,
        "checkpoint_exists": False,
        "checkpoint_readable": None,
        "checkpoint_schema_version": None,
        "checkpoint_key_id": None,
        "checkpoint_signature_valid": None,
        "checkpoint_matches_database": None,
        "checkpoint_key_status": "unknown",
        "errors": [],
        "classification": [],
    }

    checkpoint_file = checkpoint_path(
        checkpoint_directory,
        response_id,
    )

    result["checkpoint_exists"] = checkpoint_file.is_file()

    metadata = None

    if result["checkpoint_exists"]:
        metadata = _read_checkpoint_metadata(checkpoint_file)

        result["checkpoint_readable"] = metadata["readable"]
        result["checkpoint_schema_version"] = metadata["schema_version"]
        result["checkpoint_key_id"] = metadata["key_id"]

        if metadata["error"]:
            result["errors"].append(metadata["error"])

        schema_version = metadata["schema_version"]
        key_id = metadata["key_id"]

        if schema_version == 1:
            result["checkpoint_key_status"] = "legacy_v1"
        elif schema_version == 2 and key_id == active_key_id:
            result["checkpoint_key_status"] = "active_key"
        elif schema_version == 2 and key_id in keyring:
            result["checkpoint_key_status"] = "previous_key"
        elif schema_version == 2:
            result["checkpoint_key_status"] = "unknown_key"
        else:
            result["checkpoint_key_status"] = "unknown_schema"

    head = connection.execute(
        """
        SELECT response_id, event_count, final_hash
        FROM response_audit_chain_heads
        WHERE response_id = ?
        """,
        (response_id,),
    ).fetchone()

    if head is None:
        result["errors"].append("Database audit chain head is missing.")
        result["classification"].append("missing_chain_head")
    else:
        result["chain_head_exists"] = True
        result["event_count"] = head["event_count"]
        result["final_hash"] = head["final_hash"]

    try:
        record = get_response_record(connection, response_id)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        record = None
        result["errors"].append(
            f"Unable to reconstruct response record: {exc}"
        )

    if record is None:
        result["errors"].append("Response record is missing.")
        result["classification"].append("missing_response_record")
    else:
        result["record_exists"] = True

        try:
            lifecycle_result = validate_response_audit(record)
            result["lifecycle_valid"] = lifecycle_result["valid"]

            if not lifecycle_result["valid"]:
                result["errors"].extend(
                    lifecycle_result.get("errors", [])
                )
        except (KeyError, TypeError, ValueError) as exc:
            result["lifecycle_valid"] = False
            result["errors"].append(
                f"Lifecycle validation failed: {exc}"
            )

    events, event_errors = _load_audit_events(
        connection,
        response_id,
    )

    result["errors"].extend(event_errors)

    if events:
        try:
            chain_result = verify_hash_chain(events)

            result["hash_chain_valid"] = chain_result["valid"]
            result["calculated_event_count"] = chain_result.get(
                "event_count"
            )
            result["calculated_final_hash"] = chain_result.get(
                "final_hash"
            )

            if not chain_result["valid"]:
                result["errors"].extend(
                    chain_result.get("errors", [])
                )

        except (KeyError, TypeError, ValueError) as exc:
            result["hash_chain_valid"] = False
            result["errors"].append(
                f"Hash-chain verification failed: {exc}"
            )
    else:
        result["hash_chain_valid"] = False
        result["errors"].append("No audit events exist for this response.")

    if head is not None and result["hash_chain_valid"]:
        result["chain_head_matches"] = (
            result["calculated_event_count"] == head["event_count"]
            and result["calculated_final_hash"] == head["final_hash"]
        )

        if not result["chain_head_matches"]:
            result["errors"].append(
                "Calculated audit chain does not match the stored chain head."
            )

    if result["checkpoint_exists"] and head is not None:
        try:
            verification = verify_audit_checkpoint(
                response_id=response_id,
                event_count=head["event_count"],
                final_hash=head["final_hash"],
            )

            result["checkpoint_signature_valid"] = verification["valid"]

            if not verification["valid"]:
                result["errors"].extend(
                    verification.get("errors", [])
                )
            else:
                result["checkpoint_matches_database"] = True

        except (ValueError, TypeError, OSError, RuntimeError) as exc:
            result["checkpoint_signature_valid"] = False
            result["errors"].append(
                f"Checkpoint verification failed: {exc}"
            )

    elif not result["checkpoint_exists"]:
        result["classification"].append("missing_checkpoint")

    if (
        result["checkpoint_exists"]
        and result["checkpoint_signature_valid"] is True
        and result["checkpoint_key_status"] == "legacy_v1"
    ):
        result["classification"].append("legacy_checkpoint")

    if (
        result["checkpoint_exists"]
        and result["checkpoint_signature_valid"] is True
        and result["checkpoint_key_status"] == "previous_key"
    ):
        result["classification"].append("previous_key_checkpoint")

    if (
        result["checkpoint_exists"]
        and result["checkpoint_signature_valid"] is False
    ):
        result["classification"].append("invalid_checkpoint")

    if (
        result["hash_chain_valid"] is False
        or result["lifecycle_valid"] is False
        or result["chain_head_matches"] is False
    ):
        result["classification"].append("audit_integrity_failure")

    if not result["classification"]:
        result["classification"].append("inspected")

    return result


def inventory_audit_checkpoints(
    connection: sqlite3.Connection,
    checkpoint_directory: Path,
) -> dict[str, Any]:
    """
    Produce a read-only inventory of audit checkpoints and database chains.

    This function never initializes schemas, writes checkpoints, repairs
    records, or modifies existing files.
    """
    (
        _active_secret,
        active_key_id,
        keyring,
        _legacy_secret,
        configured_directory,
    ) = load_checkpoint_configuration()

    checkpoint_directory = Path(checkpoint_directory).resolve()
    configured_directory = Path(configured_directory).resolve()

    if checkpoint_directory != configured_directory:
        raise ValueError(
            "Inventory directory does not match "
            "AEGIS_AUDIT_CHECKPOINT_DIR."
        )

    if not checkpoint_directory.exists():
        discovered_files = []
    elif not checkpoint_directory.is_dir():
        raise ValueError("Checkpoint path is not a directory.")
    else:
        discovered_files = sorted(checkpoint_directory.iterdir())

    records = connection.execute(
        "SELECT id FROM response_records ORDER BY id ASC"
    ).fetchall()

    heads = connection.execute(
        "SELECT response_id FROM response_audit_chain_heads"
    ).fetchall()

    record_ids = {row["id"] for row in records}
    head_ids = {row["response_id"] for row in heads}
    database_ids = record_ids | head_ids

    checkpoint_ids = set()
    pending_intent_ids = set()
    pending_intent_files = []
    temporary_files = []
    lock_files = []
    unrecognized_files = []

    for path in discovered_files:
        if not path.is_file():
            unrecognized_files.append(path.name)
            continue

        checkpoint_match = CHECKPOINT_FILENAME_PATTERN.fullmatch(
            path.name
        )

        if checkpoint_match:
            checkpoint_ids.add(int(checkpoint_match.group(1)))
            continue

        intent_match = PENDING_INTENT_FILENAME_PATTERN.fullmatch(
            path.name
        )
        if intent_match:
            pending_intent_ids.add(int(intent_match.group(1)))
            pending_intent_files.append(path.name)
            continue

        if TEMPORARY_FILENAME_PATTERN.fullmatch(path.name):
            temporary_files.append(path.name)
            continue

        if LOCK_FILENAME_PATTERN.fullmatch(path.name):
            lock_files.append(path.name)
            continue

        unrecognized_files.append(path.name)

    response_ids = sorted(
        database_ids | checkpoint_ids | pending_intent_ids
    )

    response_results = [
        _inspect_response(
            connection=connection,
            response_id=response_id,
            checkpoint_directory=checkpoint_directory,
            active_key_id=active_key_id,
            keyring=keyring,
        )
        for response_id in response_ids
    ]

    for item in response_results:
        if item["response_id"] not in database_ids:
            if item["response_id"] in checkpoint_ids:
                item["classification"].append("orphan_checkpoint")
            if item["response_id"] in pending_intent_ids:
                item["classification"].append("orphan_checkpoint_intent")
        if item["response_id"] in pending_intent_ids:
            item["pending_checkpoint_intent"] = True
            item["classification"].append("pending_checkpoint_intent")
        else:
            item["pending_checkpoint_intent"] = False

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "database": "read_only_connection",
        "checkpoint_directory": str(checkpoint_directory),
        "active_key_id": active_key_id,
        "summary": {
            "database_response_records": len(record_ids),
            "database_chain_heads": len(head_ids),
            "checkpoint_files": len(checkpoint_ids),
            "pending_checkpoint_intents": len(pending_intent_ids),
            "temporary_files": len(temporary_files),
            "lock_files": len(lock_files),
            "unrecognized_files": len(unrecognized_files),
            "orphan_checkpoint_files": len(
                checkpoint_ids - database_ids
            ),
            "responses_inspected": len(response_results),
        },
        "pending_checkpoint_intent_files": pending_intent_files,
        "temporary_files": temporary_files,
        "lock_files": lock_files,
        "unrecognized_files": unrecognized_files,
        "responses": response_results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only AEGIS audit checkpoint inventory."
    )

    parser.add_argument(
        "--database",
        type=Path,
        default=DATABASE_PATH,
        help="Path to the AEGIS SQLite database.",
    )

    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path for writing the JSON inventory report.",
    )

    args = parser.parse_args()

    database_path = args.database.resolve()

    if not database_path.is_file():
        print(
            f"Database file does not exist: {database_path}",
            file=sys.stderr,
        )
        return 2

    try:
        (
            _active_secret,
            _active_key_id,
            _keyring,
            _legacy_secret,
            checkpoint_directory,
        ) = load_checkpoint_configuration()

        connection_uri = (
            f"{database_path.as_uri()}?mode=ro"
        )

        connection = sqlite3.connect(
            connection_uri,
            uri=True,
        )
        connection.row_factory = sqlite3.Row

        try:
            connection.execute("PRAGMA query_only = ON")

            report = inventory_audit_checkpoints(
                connection,
                Path(checkpoint_directory),
            )
        finally:
            connection.close()

        output = json.dumps(
            report,
            indent=2,
            sort_keys=True,
        )

        if args.output:
            args.output.write_text(
                output + "\n",
                encoding="utf-8",
            )
            print(f"Inventory report written to: {args.output}")
        else:
            print(output)

        return 0

    except (ValueError, OSError, sqlite3.Error, RuntimeError) as exc:
        print(
            f"Checkpoint inventory failed: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
