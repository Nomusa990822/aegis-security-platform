import sqlite3
from importlib import import_module

import pytest

from app.database import (
    SQLITE_BUSY_TIMEOUT_MS,
    get_connection,
)


main_module = import_module("app.main")


def test_connection_context_closes_handle_and_sets_sqlite_safety_pragmas(
    isolated_database,
):
    with get_connection() as connection:
        assert connection.execute("SELECT 1").fetchone()[0] == 1
        assert connection.execute(
            "PRAGMA foreign_keys"
        ).fetchone()[0] == 1
        assert connection.execute(
            "PRAGMA busy_timeout"
        ).fetchone()[0] == SQLITE_BUSY_TIMEOUT_MS

    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")


def test_connection_context_rolls_back_and_closes_after_exception(
    isolated_database,
):
    with pytest.raises(RuntimeError, match="simulated failure"):
        with get_connection() as connection:
            connection.execute(
                """
                INSERT INTO security_events (
                    event_type,
                    occurred_at,
                    received_at
                )
                VALUES (?, ?, ?)
                """,
                (
                    "database_test",
                    "2026-11-09T10:00:00+00:00",
                    "2026-11-09T10:00:00+00:00",
                ),
            )
            raise RuntimeError("simulated failure")

    with get_connection() as verification:
        count = verification.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()[0]

    assert count == 0

    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")


def test_health_endpoint_checks_live_database_connection(client):
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.json()["database"] == "connected"


def test_health_endpoint_returns_service_unavailable_when_database_fails(
    client,
    monkeypatch,
):
    def unavailable_connection():
        raise sqlite3.OperationalError("simulated database outage")

    monkeypatch.setattr(
        main_module,
        "get_connection",
        unavailable_connection,
    )

    response = client.get("/api/v1/health")

    assert response.status_code == 503
    assert response.json()["detail"] == "Database unavailable"
