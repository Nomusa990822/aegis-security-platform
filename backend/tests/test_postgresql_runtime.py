"""Application DB boundary integration tests against isolated PostgreSQL schemas."""
from __future__ import annotations

import os
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from app.database import get_connection, initialize_database
from app.dbapi_compat import dispose_postgres_engines
from app.idempotency import initialize_idempotency_schema

BACKEND_ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]


@pytest.mark.skipif(
    not os.getenv("AEGIS_TEST_POSTGRES_URL"),
    reason="PostgreSQL integration service is not configured",
)
def test_application_database_boundary_runs_on_migrated_postgresql(monkeypatch):
    base_url = os.environ["AEGIS_TEST_POSTGRES_URL"]
    schema = "aegis_runtime_" + uuid4().hex[:12]
    admin_engine = create_engine(base_url)

    try:
        with admin_engine.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))

        migration_config = Config(str(BACKEND_ROOT / "alembic.ini"))
        monkeypatch.setenv("AEGIS_ALEMBIC_ALLOW_MIGRATIONS", "1")
        with admin_engine.connect() as connection:
            connection.execute(text(f'SET search_path TO "{schema}"'))
            connection.commit()
            migration_config.attributes["connection"] = connection
            command.upgrade(migration_config, "head")

        runtime_url = make_url(base_url).update_query_dict(
            {"options": f"-csearch_path={schema}"}
        ).render_as_string(hide_password=False)
        monkeypatch.setenv("AEGIS_DATABASE_URL", runtime_url)

        initialize_database()
        initialize_idempotency_schema()

        with get_connection() as connection:
            inserted = connection.execute(
                """
                INSERT OR IGNORE INTO security_events (
                    event_type, source_ip, username, outcome, description,
                    occurred_at, received_at, source_system, external_event_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "authentication_success",
                    "198.51.100.41",
                    "synthetic-user",
                    "success",
                    "PostgreSQL adapter integration probe",
                    "2026-11-17T10:00:00+00:00",
                    "2026-11-17T10:00:01+00:00",
                    "integration-test",
                    "event-0001",
                ),
            )
            event_id = inserted.lastrowid
            assert isinstance(event_id, int)
            assert inserted.rowcount == 1

            duplicate = connection.execute(
                """
                INSERT OR IGNORE INTO security_events (
                    event_type, source_ip, username, outcome, description,
                    occurred_at, received_at, source_system, external_event_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "authentication_success",
                    "198.51.100.41",
                    "synthetic-user",
                    "success",
                    "Duplicate probe",
                    "2026-11-17T10:00:00+00:00",
                    "2026-11-17T10:00:02+00:00",
                    "integration-test",
                    "event-0001",
                ),
            )
            assert duplicate.lastrowid is None
            assert duplicate.rowcount == 0

            row = connection.execute(
                "SELECT id, event_type FROM security_events WHERE id = ?",
                (event_id,),
            ).fetchone()
            assert row["id"] == event_id
            assert row[0] == event_id
            assert row["event_type"] == "authentication_success"
            connection.commit()

            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO security_events (
                    event_type, occurred_at, received_at, source_system,
                    external_event_id
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    "authentication_failed",
                    "2026-11-17T10:01:00+00:00",
                    "2026-11-17T10:01:01+00:00",
                    "integration-test",
                    "rolled-back-event",
                ),
            )
            connection.rollback()

        with get_connection() as connection:
            count = connection.execute(
                "SELECT COUNT(*) AS count FROM security_events"
            ).fetchone()["count"]
            assert count == 1
    finally:
        dispose_postgres_engines()
        with admin_engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        admin_engine.dispose()
