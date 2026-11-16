"""Synthetic SQLite backup/restore rehearsal tests; no persistent DB is used."""
from __future__ import annotations

import json
import sqlite3
import tempfile

import pytest
from sqlalchemy import Column, ForeignKey, Integer, MetaData, Table, Text

from app.db_backup_rehearsal import run_synthetic_sqlite_backup_restore
from app.response.audit_chain import GENESIS_HASH, calculate_event_hash


metadata = MetaData()
parent = Table(
    "synthetic_parent",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("label", Text, nullable=False),
)
child = Table(
    "synthetic_child",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("parent_id", Integer, ForeignKey("synthetic_parent.id"), nullable=False),
    Column("payload", Text, nullable=False),
)
audit = Table(
    "response_audit_log",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("response_id", Integer, nullable=False),
    Column("alert_id", Integer, nullable=False),
    Column("event", Text, nullable=False),
    Column("actor", Text, nullable=False),
    Column("details", Text, nullable=False),
    Column("created_at", Text, nullable=False),
    Column("previous_hash", Text, nullable=False),
    Column("event_hash", Text, nullable=False),
)
heads = Table(
    "response_audit_chain_heads",
    metadata,
    Column("response_id", Integer, primary_key=True),
    Column("event_count", Integer, nullable=False),
    Column("final_hash", Text, nullable=False),
    Column("updated_at", Text, nullable=False),
)
TABLES = [parent, child, audit, heads]


def _source(*, tamper_audit: bool = False, orphan_child: bool = False):
    connection = sqlite3.connect(":memory:")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(
        """
        CREATE TABLE synthetic_parent (
            id INTEGER PRIMARY KEY,
            label TEXT NOT NULL
        );
        CREATE TABLE synthetic_child (
            id INTEGER PRIMARY KEY,
            parent_id INTEGER NOT NULL REFERENCES synthetic_parent(id),
            payload TEXT NOT NULL
        );
        CREATE TABLE response_audit_log (
            id INTEGER PRIMARY KEY,
            response_id INTEGER NOT NULL,
            alert_id INTEGER NOT NULL,
            event TEXT NOT NULL,
            actor TEXT NOT NULL,
            details TEXT NOT NULL,
            created_at TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL
        );
        CREATE TABLE response_audit_chain_heads (
            response_id INTEGER PRIMARY KEY,
            event_count INTEGER NOT NULL,
            final_hash TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )
    connection.execute(
        "INSERT INTO synthetic_parent VALUES (?, ?)", (4, "synthetic parent")
    )
    connection.execute(
        "INSERT INTO synthetic_child VALUES (?, ?, ?)",
        (9, 4, "unicode payload: zażółć / 数据"),
    )

    event = {
        "id": 1,
        "response_id": 17,
        "alert_id": 23,
        "event": "response_request_created",
        "actor": "synthetic-analyst",
        "details": {"action": "block_ip", "executed": False},
        "created_at": "2026-11-17T10:00:00+00:00",
        "previous_hash": GENESIS_HASH,
    }
    event["event_hash"] = calculate_event_hash(event, GENESIS_HASH)
    if tamper_audit:
        event["actor"] = "tampered-actor"
    connection.execute(
        "INSERT INTO response_audit_log VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            event["id"],
            event["response_id"],
            event["alert_id"],
            event["event"],
            event["actor"],
            json.dumps(event["details"], sort_keys=True, separators=(",", ":")),
            event["created_at"],
            event["previous_hash"],
            event["event_hash"],
        ),
    )
    connection.execute(
        "INSERT INTO response_audit_chain_heads VALUES (?, ?, ?, ?)",
        (
            17,
            1,
            event["event_hash"],
            "2026-11-17T10:00:00+00:00",
        ),
    )
    connection.commit()
    if orphan_child:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute(
            "INSERT INTO synthetic_child VALUES (?, ?, ?)",
            (10, 999, "orphan"),
        )
    connection.commit()
    return connection


def test_synthetic_backup_restore_reconciles_data_and_audit_evidence():
    source = _source()
    try:
        report = run_synthetic_sqlite_backup_restore(source, TABLES)
        assert report["verified"] is True
        assert report["persistent_backup_created"] is False
        assert report["integrity_check"] == "passed"
        assert report["foreign_key_check"] == "passed"
        assert report["audit_chain"] == {
            "responses_verified": 1,
            "events_verified": 1,
        }
        assert report["tables"]["synthetic_child"]["row_count"] == 1
        assert len(report["backup_sha256"]) == 64
        assert report["backup_size_bytes"] > 0
    finally:
        source.close()


def test_backup_restore_rejects_tampered_audit_chain_before_backup():
    source = _source(tamper_audit=True)
    try:
        with pytest.raises(ValueError, match="audit chain"):
            run_synthetic_sqlite_backup_restore(source, TABLES)
    finally:
        source.close()


def test_backup_restore_rejects_foreign_key_violation_before_backup():
    source = _source(orphan_child=True)
    try:
        with pytest.raises(ValueError, match="foreign-key check"):
            run_synthetic_sqlite_backup_restore(source, TABLES)
    finally:
        source.close()


def test_backup_restore_rejects_file_backed_source():
    with tempfile.NamedTemporaryFile(suffix=".sqlite3") as file:
        file_source = sqlite3.connect(file.name)
        try:
            with pytest.raises(ValueError, match="in-memory"):
                run_synthetic_sqlite_backup_restore(file_source, TABLES)
        finally:
            file_source.close()
