import pytest

from fastapi.testclient import TestClient

from app import database
from app.main import app


@pytest.fixture
def isolated_database(tmp_path, monkeypatch):
    """
    Give each test its own temporary SQLite database.

    The real backend/aegis.db is never used by this fixture.
    """
    test_database = tmp_path / "aegis_test.db"

    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        test_database
    )

    database.initialize_database()

    return test_database


@pytest.fixture
def client(isolated_database):
    """
    Provide a FastAPI test client.
    """
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def seeded_alert(isolated_database):
    """
    Insert a test alert into the temporary database.
    """
    with database.get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO security_alerts (
                title,
                severity,
                description,
                source_ip,
                detection_rule,
                created_at,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "Integration Test Alert",
                "high",
                "Test authentication activity",
                "198.51.100.250",
                "AEGIS-AUTH-001",
                "2026-11-03T10:00:00+00:00",
                "open"
            )
        )

        alert_id = cursor.lastrowid
        connection.commit()

    return alert_id


@pytest.fixture
def seeded_event(isolated_database):
    """
    Insert a test security event.
    """
    with database.get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO security_events (
                event_type,
                source_ip,
                username,
                outcome,
                description,
                occurred_at,
                received_at,
                destination_ip,
                destination_port,
                protocol
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "authentication_failed",
                "198.51.100.250",
                "test-user",
                "failure",
                "Integration test event",
                "2026-11-03T10:00:00+00:00",
                "2026-11-03T10:00:00+00:00",
                None,
                None,
                None
            )
        )

        event_id = cursor.lastrowid
        connection.commit()

    return event_id


@pytest.fixture
def seeded_correlation(isolated_database, seeded_alert):
    """
    Insert a test correlation case and link the test alert.
    """
    with database.get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO security_correlations (
                title,
                severity,
                source_ip,
                description,
                alert_count,
                status,
                created_at,
                updated_at,
                assigned_to
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "Integration Test Correlation",
                "high",
                "198.51.100.250",
                "Test correlated security activity",
                1,
                "open",
                "2026-11-03T10:00:00+00:00",
                "2026-11-03T10:00:00+00:00",
                None
            )
        )

        correlation_id = cursor.lastrowid

        connection.execute(
            """
            INSERT INTO security_correlation_alerts (
                correlation_id,
                alert_id,
                linked_at
            )
            VALUES (?, ?, ?)
            """,
            (
                correlation_id,
                seeded_alert,
                "2026-11-03T10:00:00+00:00"
            )
        )

        connection.commit()

    return correlation_id
