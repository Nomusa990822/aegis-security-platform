import sqlite3

import pytest

from app.iam.migrations import MIGRATIONS, apply_migrations


NOW = "2026-11-12T10:00:00+00:00"


def test_phase_2b_migration_is_additive_and_idempotent():
    connection = sqlite3.connect(":memory:")
    try:
        assert [migration.version for migration in MIGRATIONS] == [1, 2]
        assert MIGRATIONS[0].name == "initial_iam_schema"
        assert apply_migrations(connection, applied_at=NOW) == [1, 2]
        assert apply_migrations(connection, applied_at=NOW) == []
        tables = {
            row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert "iam_auth_rate_limits" in tables
        columns = {
            row[1] for row in connection.execute(
                "PRAGMA table_info(iam_auth_rate_limits)"
            )
        }
        assert columns == {
            "bucket_hash", "scope", "window_started_at",
            "failures", "blocked_until", "updated_at",
        }
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    finally:
        connection.close()


def test_migration_history_rejects_modified_checksum():
    connection = sqlite3.connect(":memory:")
    try:
        apply_migrations(connection, applied_at=NOW)
        connection.execute(
            "UPDATE iam_schema_migrations SET checksum = 'tampered' WHERE version = 1"
        )
        with pytest.raises(RuntimeError, match="history mismatch"):
            apply_migrations(connection, applied_at=NOW)
    finally:
        connection.close()


def test_migration_history_rejects_unknown_future_version():
    connection = sqlite3.connect(":memory:")
    try:
        apply_migrations(connection, applied_at=NOW)
        connection.execute(
            """INSERT INTO iam_schema_migrations
               (version, name, checksum, applied_at)
               VALUES (3, 'future', 'not-a-checksum', ?)""",
            (NOW,),
        )
        with pytest.raises(RuntimeError, match="unsupported"):
            apply_migrations(connection, applied_at=NOW)
    finally:
        connection.close()
