import os
from uuid import uuid4

import pytest

from app.dbapi_compat import (
    HybridRow,
    _qmark_to_pyformat,
    connect_postgres,
)


def test_qmark_translation_preserves_question_marks_inside_literals():
    assert _qmark_to_pyformat(
        "SELECT ?, '?', \"?\", ?"
    ) == "SELECT %s, '?', \"?\", %s"


def test_hybrid_row_supports_name_and_position_access():
    row = HybridRow({"id": 17, "name": "aegis"})
    assert row["id"] == 17
    assert row[0] == 17
    assert row[1] == "aegis"


def test_postgres_adapter_insert_ignore_lastrowid_and_rollback():
    database_url = os.getenv("AEGIS_TEST_POSTGRES_URL")
    if not database_url:
        pytest.skip("PostgreSQL integration service is not configured")

    table = f"aegis_adapter_probe_{uuid4().hex}"
    connection = connect_postgres(database_url)
    try:
        connection.execute(
            f"CREATE TABLE {table} (id BIGSERIAL PRIMARY KEY, value TEXT UNIQUE)"
        )
        connection.commit()

        # Use the production table name so this exercises the same RETURNING
        # behaviour used by the event ingestion and alert repositories.
        connection.execute("DROP TABLE IF EXISTS security_events")
        connection.execute(
            "CREATE TABLE security_events "
            "(id BIGSERIAL PRIMARY KEY, value TEXT UNIQUE)"
        )
        connection.commit()

        inserted = connection.execute(
            "INSERT INTO security_events (value) VALUES (?)", ("first",)
        )
        assert inserted.rowcount == 1
        assert isinstance(inserted.lastrowid, int)

        duplicate = connection.execute(
            "INSERT OR IGNORE INTO security_events (value) VALUES (?)",
            ("first",),
        )
        assert duplicate.rowcount == 0
        assert duplicate.lastrowid is None

        row = connection.execute(
            "SELECT id, value FROM security_events WHERE value = ?", ("first",)
        ).fetchone()
        assert row["value"] == "first"
        assert row[0] == row["id"]
        connection.commit()

        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "INSERT INTO security_events (value) VALUES (?)", ("rolled-back",)
        )
        connection.rollback()

        count = connection.execute(
            "SELECT COUNT(*) AS count FROM security_events"
        ).fetchone()["count"]
        assert count == 1
        connection.commit()
    finally:
        connection.rollback()
        connection.execute("DROP TABLE IF EXISTS security_events")
        connection.execute(f"DROP TABLE IF EXISTS {table}")
        connection.commit()
        connection.close()
