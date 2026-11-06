
import json

from app.response.audit_chain import (
    GENESIS_HASH,
    verify_hash_chain,
)
from app.response.audit_chain_storage import (
    initialize_audit_chain_storage,
)


def create_legacy_tables(connection):
    connection.execute("""
        CREATE TABLE response_records (
            id INTEGER PRIMARY KEY,
            alert_id INTEGER NOT NULL
        )
    """)

    connection.execute("""
        CREATE TABLE response_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            response_id INTEGER NOT NULL,
            alert_id INTEGER NOT NULL,
            event TEXT NOT NULL,
            actor TEXT NOT NULL,
            details TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    connection.execute(
        "INSERT INTO response_records (id, alert_id) VALUES (1, 10)"
    )

    connection.execute(
        """
        INSERT INTO response_audit_log (
            response_id, alert_id, event, actor, details, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            1,
            10,
            "response_request_created",
            "analyst-alpha",
            json.dumps({"status": "pending_approval"}),
            "2026-11-06T10:00:00+00:00",
        ),
    )

    connection.execute(
        """
        INSERT INTO response_audit_log (
            response_id, alert_id, event, actor, details, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            1,
            10,
            "response_approved",
            "approver-beta",
            json.dumps({"new_status": "approved"}),
            "2026-11-06T10:01:00+00:00",
        ),
    )


def test_migration_adds_hash_columns_and_chain_head(tmp_path):
    import sqlite3

    connection = sqlite3.connect(tmp_path / "migration.db")
    connection.row_factory = sqlite3.Row

    create_legacy_tables(connection)

    initialize_audit_chain_storage(connection)

    columns = {
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(response_audit_log)"
        ).fetchall()
    }

    assert "previous_hash" in columns
    assert "event_hash" in columns

    head = connection.execute(
        """
        SELECT *
        FROM response_audit_chain_heads
        WHERE response_id = 1
        """
    ).fetchone()

    assert head is not None
    assert head["event_count"] == 2
    assert len(head["final_hash"]) == 64

    connection.close()


def test_migration_backfills_valid_hash_chain(tmp_path):
    import sqlite3

    connection = sqlite3.connect(tmp_path / "migration.db")
    connection.row_factory = sqlite3.Row

    create_legacy_tables(connection)

    initialize_audit_chain_storage(connection)

    rows = connection.execute(
        """
        SELECT *
        FROM response_audit_log
        WHERE response_id = 1
        ORDER BY id ASC
        """
    ).fetchall()

    events = [
        {
            **dict(row),
            "details": json.loads(row["details"]),
        }
        for row in rows
    ]

    result = verify_hash_chain(events)

    assert result["valid"] is True
    assert result["errors"] == []
    assert result["event_count"] == 2
    assert events[0]["previous_hash"] == GENESIS_HASH

    connection.close()


def test_migration_is_safe_to_run_more_than_once(tmp_path):
    import sqlite3

    connection = sqlite3.connect(tmp_path / "migration.db")
    connection.row_factory = sqlite3.Row

    create_legacy_tables(connection)

    initialize_audit_chain_storage(connection)

    first_rows = connection.execute(
        """
        SELECT id, previous_hash, event_hash
        FROM response_audit_log
        ORDER BY id ASC
        """
    ).fetchall()

    initialize_audit_chain_storage(connection)

    second_rows = connection.execute(
        """
        SELECT id, previous_hash, event_hash
        FROM response_audit_log
        ORDER BY id ASC
        """
    ).fetchall()

    assert [tuple(row) for row in first_rows] == [
        tuple(row) for row in second_rows
    ]

    connection.close()


def test_migration_rejects_invalid_legacy_json(tmp_path):
    import sqlite3
    import pytest

    connection = sqlite3.connect(tmp_path / "migration.db")
    connection.row_factory = sqlite3.Row

    create_legacy_tables(connection)

    connection.execute(
        """
        UPDATE response_audit_log
        SET details = ?
        WHERE id = 1
        """,
        ("not-valid-json",),
    )

    with pytest.raises(ValueError, match="invalid JSON"):
        initialize_audit_chain_storage(connection)

    connection.close()
