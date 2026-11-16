"""Guarded one-time SQLite-to-PostgreSQL data transfer command.

The command requires a reviewed Alembic baseline in an empty PostgreSQL
database, an explicit operator confirmation, a consistent SQLite backup, and
valid response audit chains plus signed checkpoints. It never deletes or
modifies the SQLite source.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sqlite3
import sys
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, func, inspect, insert, select, text
from sqlalchemy.engine import URL

from app.db_engine import create_database_engine
from app.db_schema import metadata
from app.db_transfer import dependency_order, digest_table_rows
from app.db_transfer_rehearsal import _verify_response_audit_integrity
from app.response.audit import validate_response_audit
from app.response.audit_checkpoint import load_checkpoint_configuration, verify_audit_checkpoint

BASELINE_REVISION = "20261117_01"
CONFIRMATION = "MIGRATE AEGIS SQLITE DATA TO POSTGRESQL"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _backup_sqlite(source: Path, backup: Path) -> str:
    if not source.is_file():
        raise FileNotFoundError(f"SQLite source database does not exist: {source}")
    if source.resolve() == backup.resolve():
        raise ValueError("SQLite backup path must differ from the source path")
    if backup.exists():
        raise FileExistsError(f"Refusing to overwrite existing backup: {backup}")
    backup.parent.mkdir(parents=True, exist_ok=True)

    source_connection = sqlite3.connect(f"file:{source.resolve()}?mode=ro", uri=True)
    backup_connection = sqlite3.connect(backup)
    try:
        source_connection.backup(backup_connection)
        result = backup_connection.execute("PRAGMA quick_check").fetchone()
        if not result or result[0] != "ok":
            raise RuntimeError(f"SQLite backup quick_check failed: {result}")
    finally:
        backup_connection.close()
        source_connection.close()
    return _sha256(backup)


def _copy_checkpoint_directory(backup: Path) -> Path:
    _, _, _, _, source_directory = load_checkpoint_configuration()
    source_directory = Path(source_directory)
    backup_directory = Path(str(backup) + ".audit_checkpoints")
    if backup_directory.exists():
        raise FileExistsError(
            f"Refusing to overwrite checkpoint backup: {backup_directory}"
        )
    if source_directory.exists():
        shutil.copytree(source_directory, backup_directory)
    else:
        backup_directory.mkdir(parents=True)
    return backup_directory


def _verify_source_schema(connection: Any) -> None:
    inspector = inspect(connection)
    source_tables = set(inspector.get_table_names())
    expected_tables = set(metadata.tables)
    missing_tables = sorted(expected_tables - source_tables)
    if missing_tables:
        raise RuntimeError(
            "SQLite schema is missing required tables: " + ", ".join(missing_tables)
        )

    mismatches = []
    for name, table in metadata.tables.items():
        actual = {column["name"] for column in inspector.get_columns(name)}
        expected = set(table.columns.keys())
        if actual != expected:
            mismatches.append(
                f"{name}: missing={sorted(expected - actual)}, "
                f"unexpected={sorted(actual - expected)}"
            )
    if mismatches:
        raise RuntimeError(
            "SQLite schema does not match the reviewed PostgreSQL baseline: "
            + "; ".join(mismatches)
        )

    violations = connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall()
    if violations:
        raise RuntimeError(
            f"SQLite source contains {len(violations)} foreign-key violations"
        )


def _verify_response_lifecycle(connection: Any) -> int:
    from app.db_schema import metadata as schema

    records_table = schema.tables["response_records"]
    audit_table = schema.tables["response_audit_log"]
    records = connection.execute(select(records_table)).mappings().all()
    events = connection.execute(
        select(audit_table).order_by(audit_table.c.response_id, audit_table.c.id)
    ).mappings().all()

    events_by_response: dict[int, list[dict[str, Any]]] = {}
    for source_event in events:
        event = dict(source_event)
        try:
            event["details"] = json.loads(event["details"])
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"Response audit event {event.get('id')} contains invalid JSON"
            ) from exc
        events_by_response.setdefault(event["response_id"], []).append(event)

    for source_record in records:
        record = dict(source_record)
        try:
            record["reasons"] = json.loads(record["reasons"])
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"Response {record.get('id')} contains invalid reasons JSON"
            ) from exc
        for field in ("policy_allowed", "approval_required", "executed", "simulated"):
            record[field] = bool(record[field])
        record["audit_log"] = events_by_response.get(record["id"], [])
        result = validate_response_audit(record)
        if not result["valid"]:
            raise RuntimeError(
                f"Response lifecycle {record['id']} is invalid: "
                + "; ".join(result["errors"])
            )

    if set(events_by_response) - {record["id"] for record in records}:
        raise RuntimeError("Response audit log contains orphaned response IDs")
    return len(records)


def _verify_signed_checkpoints(connection: Any) -> int:
    heads = metadata.tables["response_audit_chain_heads"]
    rows = connection.execute(select(heads)).mappings().all()
    for row in rows:
        result = verify_audit_checkpoint(
            response_id=row["response_id"],
            event_count=row["event_count"],
            final_hash=row["final_hash"],
        )
        if not result["valid"]:
            raise RuntimeError(
                f"Signed checkpoint for response {row['response_id']} is invalid: "
                + "; ".join(result["errors"])
            )
    return len(rows)


def _check_target(connection: Any) -> None:
    revision = connection.execute(
        text("SELECT version_num FROM alembic_version")
    ).scalar_one_or_none()
    if revision != BASELINE_REVISION:
        raise RuntimeError(
            f"PostgreSQL target must be at Alembic revision {BASELINE_REVISION}; "
            f"found {revision!r}"
        )

    inspector = inspect(connection)
    missing = sorted(set(metadata.tables) - set(inspector.get_table_names()))
    if missing:
        raise RuntimeError(
            "PostgreSQL target is missing baseline tables: " + ", ".join(missing)
        )

    populated = []
    for name, table in metadata.tables.items():
        count = connection.execute(
            select(func.count()).select_from(table)
        ).scalar_one()
        if count:
            populated.append(f"{name}={count}")
    if populated:
        raise RuntimeError(
            "PostgreSQL target is not empty; refusing to mix datasets: "
            + ", ".join(populated)
        )


def _transfer(source_connection: Any, destination_connection: Any) -> dict[str, dict[str, Any]]:
    tables = list(metadata.tables.values())
    order = dependency_order(tables)
    _verify_response_audit_integrity(source_connection, tables)
    _verify_response_lifecycle(source_connection)
    _verify_signed_checkpoints(source_connection)

    manifest: dict[str, dict[str, Any]] = {}
    by_name = {table.name: table for table in tables}
    for name in order:
        table = by_name[name]
        source_rows = [
            dict(row._mapping)
            for row in source_connection.execute(
                select(table).order_by(*tuple(table.primary_key.columns))
            )
        ]
        source_digest = digest_table_rows(table, source_rows)

        for offset in range(0, len(source_rows), 1000):
            batch = source_rows[offset:offset + 1000]
            if batch:
                destination_connection.execute(insert(table), batch)

        destination_rows = [
            dict(row._mapping)
            for row in destination_connection.execute(
                select(table).order_by(*tuple(table.primary_key.columns))
            )
        ]
        destination_digest = digest_table_rows(table, destination_rows)
        if len(source_rows) != len(destination_rows):
            raise RuntimeError(f"Row-count reconciliation failed for {name}")
        if source_digest != destination_digest:
            raise RuntimeError(f"SHA-256 content reconciliation failed for {name}")

        manifest[name] = {
            "row_count": len(source_rows),
            "sha256": source_digest,
            "verified": True,
        }

    for table in tables:
        for column in table.primary_key.columns:
            try:
                is_integer = column.type.python_type is int
            except (AttributeError, NotImplementedError):
                is_integer = False
            if not is_integer or column.autoincrement is False:
                continue
            sequence = destination_connection.execute(
                select(func.pg_get_serial_sequence(table.name, column.name))
            ).scalar_one_or_none()
            if not sequence:
                continue
            maximum = destination_connection.execute(
                select(func.max(column)).select_from(table)
            ).scalar_one_or_none()
            if maximum is not None:
                destination_connection.execute(
                    select(func.setval(sequence, maximum, maximum > 0))
                )

    _verify_response_audit_integrity(destination_connection, tables)
    _verify_response_lifecycle(destination_connection)
    _verify_signed_checkpoints(destination_connection)
    return manifest


def migrate(source_path: Path, backup_path: Path, confirmation: str) -> dict[str, Any]:
    if confirmation != CONFIRMATION:
        raise ValueError(
            "Explicit confirmation required. Pass --confirm with the exact phrase: "
            + CONFIRMATION
        )

    source_path = source_path.expanduser().resolve()
    backup_path = backup_path.expanduser().resolve()
    backup_sha256 = _backup_sqlite(source_path, backup_path)
    checkpoint_backup = _copy_checkpoint_directory(backup_path)

    source_url = URL.create(
        "sqlite+pysqlite",
        database=str(source_path),
    )
    source_engine = create_engine(source_url)
    destination_engine = create_database_engine()

    try:
        with source_engine.connect() as source_connection:
            # Acquire SQLite's reserved writer lock for the entire transfer so
            # an old AEGIS process cannot append events during the snapshot.
            source_connection.exec_driver_sql("BEGIN IMMEDIATE")
            _verify_source_schema(source_connection)

            with destination_engine.begin() as destination_connection:
                _check_target(destination_connection)
                manifest = _transfer(source_connection, destination_connection)

            return {
                "status": "verified",
                "source_database": str(source_path),
                "source_backup": str(backup_path),
                "source_backup_sha256": backup_sha256,
                "audit_checkpoint_backup": str(checkpoint_backup),
                "table_count": len(manifest),
                "row_count": sum(item["row_count"] for item in manifest.values()),
                "response_audit_chains_verified": True,
                "signed_checkpoints_verified": True,
                "tables": manifest,
            }
    finally:
        source_engine.dispose()
        destination_engine.dispose()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Back up and transfer AEGIS SQLite data into a migrated PostgreSQL database."
    )
    parser.add_argument("--source", type=Path, required=True, help="Existing SQLite database file")
    parser.add_argument("--backup", type=Path, required=True, help="New SQLite backup file path")
    parser.add_argument(
        "--confirm",
        required=True,
        help=f"Exact confirmation phrase: {CONFIRMATION}",
    )
    args = parser.parse_args()

    try:
        result = migrate(args.source, args.backup, args.confirm)
    except Exception as exc:
        print(f"TRANSFER FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
