import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

from app.database import DATABASE_PATH
from app.response.audit_checkpoint import write_audit_checkpoint
from app.response.checkpoint_inventory import (
    _inspect_response,
    inventory_audit_checkpoints,
)
from app.response.audit_checkpoint import load_checkpoint_configuration


def _is_bootstrap_candidate(item: dict[str, Any]) -> bool:
    """Return True only for a complete, verified chain with no checkpoint."""
    return (
        item.get("record_exists") is True
        and item.get("chain_head_exists") is True
        and item.get("event_count", 0) > 0
        and item.get("lifecycle_valid") is True
        and item.get("hash_chain_valid") is True
        and item.get("chain_head_matches") is True
        and item.get("checkpoint_exists") is False
        and item.get("pending_checkpoint_intent") is False
        and item.get("calculated_event_count") == item.get("event_count")
        and item.get("calculated_final_hash") == item.get("final_hash")
        and item.get("errors") == []
        and "orphan_checkpoint" not in item.get("classification", [])
    )


def _candidate_reasons(item: dict[str, Any]) -> list[str]:
    """Explain why an inspected response cannot be bootstrapped."""
    reasons = list(item.get("errors", []))

    checks = (
        ("record_exists", "Response record is missing."),
        ("chain_head_exists", "Database audit-chain head is missing."),
        ("lifecycle_valid", "Response lifecycle is not valid."),
        ("hash_chain_valid", "Audit hash chain is not valid."),
        ("chain_head_matches", "Calculated chain does not match the stored head."),
    )

    for field, message in checks:
        if item.get(field) is not True and message not in reasons:
            reasons.append(message)

    if item.get("checkpoint_exists"):
        reasons.append("A checkpoint already exists; it will not be overwritten.")

    if item.get("pending_checkpoint_intent"):
        reasons.append(
            "A signed pending checkpoint intent exists; use the recovery workflow."
        )

    if "orphan_checkpoint" in item.get("classification", []):
        reasons.append("Checkpoint is orphaned from the database.")

    if item.get("event_count", 0) <= 0:
        reasons.append("Audit chain has no events to checkpoint.")

    return reasons


def bootstrap_audit_checkpoints(
    connection: sqlite3.Connection,
    checkpoint_directory: Path,
    *,
    apply: bool = False,
    response_ids: set[int] | None = None,
) -> dict[str, Any]:
    """
    Plan or create initial checkpoints for fully verified audit chains.

    The SQLite connection must be read-only. Dry-run is the default.
    This function never changes database records or audit-chain state.
    """
    if response_ids is not None:
        if not response_ids:
            raise ValueError("At least one response ID must be selected.")

        if any(
            not isinstance(response_id, int)
            or isinstance(response_id, bool)
            or response_id < 1
            for response_id in response_ids
        ):
            raise ValueError("Response IDs must be positive integers.")

    initial_inventory = inventory_audit_checkpoints(
        connection,
        checkpoint_directory,
    )

    inspected = {
        item["response_id"]: item
        for item in initial_inventory["responses"]
    }

    selected_ids = (
        sorted(inspected)
        if response_ids is None
        else sorted(response_ids)
    )

    report: dict[str, Any] = {
        "mode": "apply" if apply else "dry_run",
        "database": "read_only_connection",
        "checkpoint_directory": initial_inventory["checkpoint_directory"],
        "active_key_id": initial_inventory["active_key_id"],
        "selected_response_ids": selected_ids,
        "eligible_response_ids": [],
        "created_response_ids": [],
        "skipped": [],
        "errors": [],
    }

    for response_id in selected_ids:
        item = inspected.get(response_id)

        if item is None:
            report["skipped"].append({
                "response_id": response_id,
                "reasons": ["No matching response record or checkpoint was found."],
            })
            continue

        if _is_bootstrap_candidate(item):
            report["eligible_response_ids"].append(response_id)
        else:
            report["skipped"].append({
                "response_id": response_id,
                "reasons": _candidate_reasons(item),
            })

    if not apply:
        report["planned_response_ids"] = list(
            report["eligible_response_ids"]
        )
        return report

    if report["eligible_response_ids"]:
        Path(checkpoint_directory).mkdir(
            parents=True,
            exist_ok=True,
            mode=0o700,
        )

    for response_id in report["eligible_response_ids"]:
        try:
            # Reinspect immediately before signing. The normal writer then
            # obtains its per-response lock and refuses an existing file.
            fresh_inventory = inventory_audit_checkpoints(
                connection,
                checkpoint_directory,
            )
            fresh_item = next(
                (
                    item
                    for item in fresh_inventory["responses"]
                    if item["response_id"] == response_id
                ),
                None,
            )

            if fresh_item is None or not _is_bootstrap_candidate(fresh_item):
                reasons = (
                    ["Response disappeared from the inventory."]
                    if fresh_item is None
                    else _candidate_reasons(fresh_item)
                )
                report["skipped"].append({
                    "response_id": response_id,
                    "reasons": [
                        "Eligibility changed during bootstrap.",
                        *reasons,
                    ],
                })
                continue

            write_audit_checkpoint(
                response_id=response_id,
                event_count=fresh_item["event_count"],
                final_hash=fresh_item["final_hash"],
            )

            verified_inventory = inventory_audit_checkpoints(
                connection,
                checkpoint_directory,
            )
            verified_item = next(
                (
                    item
                    for item in verified_inventory["responses"]
                    if item["response_id"] == response_id
                ),
                None,
            )

            if (
                verified_item is None
                or verified_item.get("checkpoint_signature_valid") is not True
                or verified_item.get("checkpoint_matches_database") is not True
                or verified_item.get("checkpoint_key_status") != "active_key"
            ):
                raise RuntimeError(
                    "Post-write checkpoint verification failed. "
                    "The checkpoint was preserved for investigation."
                )

            report["created_response_ids"].append(response_id)

        except (OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
            report["errors"].append({
                "response_id": response_id,
                "error": str(exc),
            })

    report["post_write_inventory"] = inventory_audit_checkpoints(
        connection,
        checkpoint_directory,
    )

    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Bootstrap missing AEGIS audit checkpoints. "
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
        help="Limit the operation to this response ID. May be repeated.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Create eligible checkpoints. Without this flag, no files are created.",
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
        (
            _active_secret,
            _active_key_id,
            _keyring,
            _legacy_secret,
            checkpoint_directory,
        ) = load_checkpoint_configuration()

        connection_uri = f"{database_path.as_uri()}?mode=ro"
        connection = sqlite3.connect(connection_uri, uri=True)
        connection.row_factory = sqlite3.Row

        try:
            connection.execute("PRAGMA query_only = ON")

            report = bootstrap_audit_checkpoints(
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

    except (ValueError, OSError, sqlite3.Error, RuntimeError) as exc:
        print(
            f"Checkpoint bootstrap failed: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
