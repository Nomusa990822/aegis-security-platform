from importlib import import_module

from app.database import get_connection


main_module = import_module("app.main")


def test_detection_failure_rolls_back_entire_ingestion_transaction(
    client,
    isolated_database,
    monkeypatch,
):
    payload = {
        "source_system": "atomicity-test-agent",
        "external_event_id": "atomicity-event-001",
        "event_type": "heartbeat",
        "source_ip": "192.0.2.150",
        "description": "Transaction atomicity test",
    }

    original_evaluate_event = main_module.evaluate_event

    def failing_detection(connection, event):
        connection.execute(
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
                "Temporary Test Alert",
                "high",
                "Alert created before simulated failure",
                "192.0.2.150",
                "AEGIS-TEST-001",
                "2026-11-06T10:00:00+00:00",
                "open",
            ),
        )

        raise RuntimeError("Simulated detection engine failure")

    monkeypatch.setattr(
        main_module,
        "evaluate_event",
        failing_detection,
    )

    # --------------------------------------------------
    # 1. SIMULATE DETECTION FAILURE
    # --------------------------------------------------

    failed_response = client.post(
        "/api/v1/events",
        json=payload,
    )

    assert failed_response.status_code == 500

    # --------------------------------------------------
    # 2. VERIFY COMPLETE ROLLBACK
    # --------------------------------------------------

    with get_connection() as connection:

        event_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM security_events
            WHERE source_system = ?
            AND external_event_id = ?
            """,
            (
                payload["source_system"],
                payload["external_event_id"],
            ),
        ).fetchone()[0]

        alert_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM security_alerts
            WHERE detection_rule = ?
            """,
            ("AEGIS-TEST-001",),
        ).fetchone()[0]

    assert event_count == 0
    assert alert_count == 0

    # --------------------------------------------------
    # 3. RESTORE DETECTION ENGINE
    # --------------------------------------------------

    monkeypatch.setattr(
        main_module,
        "evaluate_event",
        original_evaluate_event,
    )

    # --------------------------------------------------
    # 4. RETRY THE SAME EVENT IDENTITY
    # --------------------------------------------------

    retry_response = client.post(
        "/api/v1/events",
        json=payload,
    )

    assert retry_response.status_code == 201

    retry_result = retry_response.json()

    assert retry_result["duplicate"] is False
    assert retry_result["event_id"] is not None

    # --------------------------------------------------
    # 5. VERIFY SUCCESSFUL PERSISTENCE
    # --------------------------------------------------

    with get_connection() as connection:

        persisted_event = connection.execute(
            """
            SELECT id
            FROM security_events
            WHERE source_system = ?
            AND external_event_id = ?
            """,
            (
                payload["source_system"],
                payload["external_event_id"],
            ),
        ).fetchone()

        total_events = connection.execute(
            """
            SELECT COUNT(*)
            FROM security_events
            """
        ).fetchone()[0]

    assert persisted_event is not None

    assert persisted_event["id"] == retry_result["event_id"]

    assert total_events == 1
