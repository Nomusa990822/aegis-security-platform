from app import main as main_module
from app.database import get_connection


def test_enrichment_failure_does_not_fail_event_ingestion(
    client,
    isolated_database,
    monkeypatch,
):
    async def fail_enrichment(*, alert_id, source_ip):
        raise RuntimeError(
            "Simulated threat intelligence provider failure"
        )

    def fake_evaluate_event(connection, event):
        return [
            {
                "alert_id": 98765,
                "rule_id": "AEGIS-TEST-001",
                "severity": "high",
            }
        ]

    monkeypatch.setattr(
        main_module,
        "evaluate_event",
        fake_evaluate_event,
    )

    monkeypatch.setattr(
        main_module.alert_intelligence_service,
        "enrich_alert",
        fail_enrichment,
    )

    payload = {
        "source_system": "enrichment-failure-test",
        "external_event_id": "enrichment-failure-001",
        "event_type": "authentication",
        "source_ip": "203.0.113.45",
        "username": "test_user",
        "outcome": "failure",
        "description": "Test event for enrichment failure isolation",
    }

    response = client.post(
        "/api/v1/events",
        json=payload,
    )

    assert response.status_code == 201

    result = response.json()

    assert result["duplicate"] is False
    assert result["event_id"] is not None
    assert result["detection_count"] == 1

    assert len(result["intelligence_enrichments"]) == 1

    enrichment = result["intelligence_enrichments"][0]

    assert enrichment["alert_id"] == 98765
    assert enrichment["status"] == "failed"

    with get_connection() as connection:
        stored_event = connection.execute(
            """
            SELECT id, external_event_id
            FROM security_events
            WHERE source_system = ?
            AND external_event_id = ?
            """,
            (
                "enrichment-failure-test",
                "enrichment-failure-001",
            ),
        ).fetchone()

    assert stored_event is not None
    assert stored_event["id"] == result["event_id"]
