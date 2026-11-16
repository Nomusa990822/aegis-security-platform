"""Synthetic-only SQLite backup/restore rehearsal using SQLite's backup API.

The source must be an in-memory SQLite database. The backup is written only
inside a private temporary directory and restored into a fresh in-memory
SQLite database. No configured application path or persistent backup target
is accepted.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from sqlalchemy import Table

from app.db_transfer import digest_table_rows


def _assert_memory_database(connection: sqlite3.Connection, label: str) -> None:
    databases = connection.execute("PRAGMA database_list").fetchall()
    main = next((row for row in databases if row[1] == "main"), None)
    if main is None or main[2] not in ("", None):
        raise ValueError(f"{label} must be an in-memory SQLite database")


def _integrity_report(connection: sqlite3.Connection, label: str) -> None:
    result = connection.execute("PRAGMA integrity_check").fetchall()
    if result != [("ok",)]:
        raise ValueError(f"{label} SQLite integrity check failed: {result!r}")
    violations = connection.execute("PRAGMA foreign_key_check").fetchall()
    if violations:
        raise ValueError(
            f"{label} SQLite foreign-key check failed: {len(violations)} violation(s)"
        )


def _table_rows(
    connection: sqlite3.Connection,
    table: Table,
) -> list[dict[str, Any]]:
    quote = lambda value: '"' + value.replace('"', '""') + '"'
    order = ", ".join(quote(column.name) for column in table.primary_key.columns)
    rows = connection.execute(
        f"SELECT * FROM {quote(table.name)} ORDER BY {order}"
    ).fetchall()
    columns = [column.name for column in table.columns]
    return [dict(zip(columns, row, strict=True)) for row in rows]


def _verify_audit_chain(
    connection: sqlite3.Connection,
    table_names: set[str],
) -> dict[str, int]:
    audit_name = "response_audit_log"
    heads_name = "response_audit_chain_heads"
    if audit_name not in table_names and heads_name not in table_names:
        return {"responses_verified": 0, "events_verified": 0}
    if audit_name not in table_names or heads_name not in table_names:
        raise ValueError("backup requires both response audit events and chain-head tables")

    from app.response.audit_chain import verify_hash_chain

    events_by_response: dict[int, list[dict[str, Any]]] = {}
    rows = connection.execute(
        'SELECT * FROM "response_audit_log" ORDER BY response_id, id'
    ).fetchall()
    columns = [item[1] for item in connection.execute(
        'PRAGMA table_info("response_audit_log")'
    )]
    for raw in rows:
        event = dict(zip(columns, raw, strict=True))
        try:
            event["details"] = json.loads(event["details"])
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("backup contains invalid response audit details JSON") from exc
        if not isinstance(event["details"], dict):
            raise ValueError("response audit details must be a JSON object")
        events_by_response.setdefault(event["response_id"], []).append(event)

    head_rows = connection.execute(
        'SELECT response_id, event_count, final_hash FROM "response_audit_chain_heads"'
    ).fetchall()
    heads = {row[0]: {"event_count": row[1], "final_hash": row[2]} for row in head_rows}
    if set(events_by_response) != set(heads):
        raise ValueError("backup response audit events and chain-head IDs do not match")

    event_count = 0
    for response_id, events in events_by_response.items():
        result = verify_hash_chain(events)
        if not result["valid"]:
            raise ValueError(
                f"backup response audit chain {response_id} is invalid: "
                + "; ".join(result["errors"])
            )
        head = heads[response_id]
        if head["event_count"] != result["event_count"]:
            raise ValueError(f"backup response audit event count mismatch for {response_id}")
        if head["final_hash"] != result["final_hash"]:
            raise ValueError(f"backup response audit final hash mismatch for {response_id}")
        event_count += result["event_count"]
    return {"responses_verified": len(events_by_response), "events_verified": event_count}


def _verify_tables(
    connection: sqlite3.Connection,
    tables: Sequence[Table],
) -> dict[str, dict[str, Any]]:
    expected = {table.name for table in tables}
    actual = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }
    if actual != expected:
        raise ValueError(
            f"backup table inventory mismatch: missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )

    manifest: dict[str, dict[str, Any]] = {}
    for table in tables:
        rows = _table_rows(connection, table)
        manifest[table.name] = {
            "row_count": len(rows),
            "sha256": digest_table_rows(table, rows),
            "verified": True,
        }
    return manifest


def run_synthetic_sqlite_backup_restore(
    source: sqlite3.Connection,
    tables: Sequence[Table],
) -> dict[str, Any]:
    """Back up an in-memory SQLite fixture to a temporary file and restore it.

    The temporary backup is always removed before return. Both source and
    restored databases must be in-memory SQLite connections. The function
    performs no migrations and never accepts a filesystem path.
    """
    if not tables:
        raise ValueError("backup rehearsal requires an explicit non-empty table set")
    if len({table.name for table in tables}) != len(tables):
        raise ValueError("backup rehearsal table names must be unique")
    _assert_memory_database(source, "backup source")
    _integrity_report(source, "source")
    source_audit = _verify_audit_chain(source, {table.name for table in tables})
    source_manifest = _verify_tables(source, tables)

    with tempfile.TemporaryDirectory(prefix="aegis-synthetic-backup-") as directory:
        backup_path = Path(directory) / "synthetic-backup.sqlite3"
        with sqlite3.connect(backup_path) as backup:
            source.backup(backup)
            _integrity_report(backup, "backup")
        backup_bytes = backup_path.read_bytes()
        backup_sha256 = hashlib.sha256(backup_bytes).hexdigest()

        restored = sqlite3.connect(":memory:")
        try:
            restored.execute("PRAGMA foreign_keys = ON")
            with sqlite3.connect(
                f"file:{backup_path.as_posix()}?mode=ro", uri=True
            ) as backup_source:
                _integrity_report(backup_source, "backup source")
                backup_source.backup(restored)
            _integrity_report(restored, "restored")
            restored_manifest = _verify_tables(restored, tables)
            restored_audit = _verify_audit_chain(
                restored, {table.name for table in tables}
            )
            if source_manifest != restored_manifest:
                raise ValueError("restored backup content reconciliation failed")
            if source_audit != restored_audit:
                raise ValueError("restored backup audit evidence reconciliation failed")
        finally:
            restored.close()

    return {
        "source": "in-memory synthetic SQLite",
        "backup": "temporary SQLite backup API artifact",
        "restore": "fresh in-memory SQLite database",
        "backup_size_bytes": len(backup_bytes),
        "backup_sha256": backup_sha256,
        "integrity_check": "passed",
        "foreign_key_check": "passed",
        "audit_chain": source_audit,
        "tables": restored_manifest,
        "verified": True,
        "persistent_backup_created": False,
    }
