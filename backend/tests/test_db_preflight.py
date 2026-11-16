"""Tests for the explicit-path, read-only SQLite preflight."""
from __future__ import annotations

import sqlite3

import pytest

from app import database
from app.db_preflight import inspect_sqlite_schema_read_only
from app.iam.migrations import apply_migrations
from app.idempotency import initialize_idempotency_schema


def _build_reference(path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", path)
    database.initialize_database()
    with database.get_connection() as connection:
        apply_migrations(connection, applied_at="2026-11-16T12:00:00+00:00")
    initialize_idempotency_schema()


def test_read_only_preflight_reports_reference_schema_without_exposing_rows(
    tmp_path, monkeypatch
):
    path = tmp_path / "preflight-reference.db"
    _build_reference(path, monkeypatch)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO security_events "
            "(event_type, occurred_at, received_at) VALUES (?, ?, ?)",
            ("synthetic-preflight-event", "t1", "t1"),
        )
        connection.commit()
    before = path.read_bytes()

    report = inspect_sqlite_schema_read_only(path)

    assert report["integrity_check"] == "ok"
    assert report["foreign_key_violations"] == 0
    assert report["expected_table_count"] == report["actual_table_count"]
    assert report["compatible_for_baseline"] is True
    assert all("synthetic-preflight-event" not in str(value) for value in report.values())
    assert path.read_bytes() == before
    assert report["limitations"]


def test_read_only_preflight_rejects_missing_path_without_creating_file(tmp_path):
    missing = tmp_path / "must-not-be-created.db"
    with pytest.raises(ValueError, match="existing regular file"):
        inspect_sqlite_schema_read_only(missing)
    assert not missing.exists()


def test_read_only_preflight_rejects_symlink(tmp_path, monkeypatch):
    target = tmp_path / "real.db"
    _build_reference(target, monkeypatch)
    link = tmp_path / "linked.db"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symbolic-link"):
        inspect_sqlite_schema_read_only(link)
