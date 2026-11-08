import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any

from app.database import DATABASE_PATH
from app.response.audit import validate_response_audit
from app.response.audit_chain import verify_hash_chain
from app.response.audit_checkpoint import load_checkpoint_configuration
from app.response.checkpoint_intent import (
    checkpoint_intent_path,
    publish_checkpoint_intent,
    verify_checkpoint_intent,
)
from app.response.repository import get_response_record


INTENT_FILENAME_PATTERN = re.compile(
    r"^response_([1-9][0-9]*)\.pending\.json$"
)


def _validate_recovery_candidate(
    connection: sqlite3.Connection,
    response_id: int,
) -> dict[str, Any]:
    intent_result = verify_checkpoint_intent(response_id)
    if not intent_result["valid"]:
        return {
            "eligible": False,
            "errors": intent_result["errors"],
        }

    intent = intent_result["intent"]
    record = get_response_record(connection, response_id)
    if record is None:
        return {
            "eligible": False,
            "errors": ["Response record is missing."],
        }

    lifecycle = validate_response_audit(record)
    if not lifecycle["valid"]:
        return {
            "eligible": False,
            "errors": [
                "Response lifecycle is invalid: " + "; ".join(lifecycle["errors"])
            ],
        }

    chain = verify_hash_chain(record["audit_log"])
    if not chain["valid"]:
        return {
            "eligible": False,
            "errors": [
                "Audit hash chain is invalid: " + "; ".join(chain["errors"])
            ],
        }

    head = connection.execute(
        """
        SELECT event_count, final_hash
        FROM response_audit_chain_heads
        WHERE response_id = ?
        """,
        (response_id,),
    ).fetchone()

    if head is None:
        return {
            "eligible": False,
            "errors": ["Database audit-chain head is missing."],
        }

    if (
        head["event_count"] != chain["event_count"]
        or head["final_hash"] != chain["final_hash"]
    ):
        return {
            "eligible": False,
            "errors": ["Database audit-chain head does not match the verified chain."],
        }

    if (
        intent["event_count"] != chain["event_count"]
        or intent["final_hash"] != chain["final_hash"]
    ):
        return {
            "eligible": False,
            "errors": [
                "Current database audit head does not match the signed intent."
            ],
        }

    previous_count = intent["previous_event_count"]
    previous_hash = intent["previous_final_hash"]
    events = record["audit_log"]

    if previous_count != len(events) - 1:
        return {
            "eligible": False,
            "errors": ["Signed intent predecessor count does not match the audit history."],
        }

    expected_previous_hash = (
        "0" * 64
        if previous_count == 0
        else events[-2]["event_hash"]
    )
    if previous_hash != expected_previous_hash:
        return {
            "eligible": False,
            "errors": ["Signed intent predecessor hash does not match the audit history."],
        }

    return {
        "eligible": True,
        "errors": [],
        "event_count": chain["event_count"],
        "final_hash": chain["final_hash"],
    }


def recover_checkpoint_intents(
    connection: sqlite3.Connection,
    checkpoint_directory: Path,
    *,
    apply: bool = False,
    response_ids: set[int] | None = None,
) -> dict[str, Any]:
    """Inspect or publish signed intents; never modify the SQLite database."""
    checkpoint_directory = Path(checkpoint_directory).resolve()
    configured_directory = Path(
        load_checkpoint_configuration()[4]
    ).resolve()

    if checkpoint_directory != configured_directory:
        raise ValueError(
            "Recovery directory does not match AEGIS_AUDIT_CHECKPOINT_DIR."
        )

    if response_ids is not None:
        if not response_ids:
            raise ValueError("At least one response ID must be selected.")
        if any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 1
            for value in response_ids
        ):
            raise ValueError("Response IDs must be positive integers.")

    intent_ids = set()
    if checkpoint_directory.exists():
        if not checkpoint_directory.is_dir():
            raise ValueError("Checkpoint path is not a directory.")
        for path in checkpoint_directory.iterdir():
            match = INTENT_FILENAME_PATTERN.fullmatch(path.name)
            if match and path.is_file():
                intent_ids.add(int(match.group(1)))

    selected_ids = (
        sorted(intent_ids)
        if response_ids is None
        else sorted(response_ids)
    )

    report: dict[str, Any] = {
        "mode": "apply" if apply else "dry_run",
        "database": "read_only_connection",
        "checkpoint_directory": str(checkpoint_directory),
        "discovered_intent_ids": sorted(intent_ids),
        "selected_response_ids": selected_ids,
        "eligible_response_ids": [],
        "recovered_response_ids": [],
        "skipped": [],
        "errors": [],
    }

    for response_id in selected_ids:
        intent_path = checkpoint_intent_path(
            checkpoint_directory,
            response_id,
        )
        if not intent_path.is_file():
            report["skipped"].append({
                "response_id": response_id,
                "reasons": ["Pending checkpoint intent file does not exist."],
            })
            continue

        candidate = _validate_recovery_candidate(
            connection,
            response_id,
        )
        if not candidate["eligible"]:
            report["skipped"].append({
                "response_id": response_id,
                "reasons": candidate["errors"],
            })
            continue

        report["eligible_response_ids"].append(response_id)

        if not apply:
            continue

        try:
            publish_checkpoint_intent(
                response_id=response_id,
                event_count=candidate["event_count"],
                final_hash=candidate["final_hash"],
            )
            report["recovered_response_ids"].append(response_id)
        except (OSError, RuntimeError, ValueError) as exc:
            report["errors"].append({
                "response_id": response_id,
                "error": str(exc),
            })

    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Recover signed AEGIS checkpoint intents. "
            "Defaults to a read-only dry run."
        )
    )
    parser.add_argument(
        "--database",
        type=Path,
        default=DATABASE_PATH,
        help="Path to the AEGIS SQLite database.",
    )
    parser.add_argument(
        "--response-id",
        type=int,
        action="append",
        dest="response_ids",
        help="Limit recovery to this response ID. May be repeated.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Publish eligible checkpoints. Without this flag, no files are changed.",
    )
    args = parser.parse_args(argv)

    database_path = args.database.resolve()
    if not database_path.is_file():
        print(
            f"Database file does not exist: {database_path}",
            file=sys.stderr,
        )
        return 2

    try:
        checkpoint_directory = load_checkpoint_configuration()[4]
        connection = sqlite3.connect(
            f"{database_path.as_uri()}?mode=ro",
            uri=True,
        )
        connection.row_factory = sqlite3.Row

        try:
            connection.execute("PRAGMA query_only = ON")
            report = recover_checkpoint_intents(
                connection,
                Path(checkpoint_directory),
                apply=args.apply,
                response_ids=(
                    set(args.response_ids)
                    if args.response_ids is not None
                    else None
                ),
            )
        finally:
            connection.close()

        print(json.dumps(report, indent=2, sort_keys=True))

        if report["errors"]:
            return 1
        if args.apply and report["skipped"]:
            return 1
        return 0

    except (OSError, ValueError, sqlite3.Error, RuntimeError) as exc:
        print(f"Checkpoint recovery failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
