
from app.database import get_connection


def make_payload(
    external_event_id,
    source_system="test-siem",
    username="administrator",
    event_type="authentication",
    outcome="failure",
):
    return {
        "source_system": source_system,
        "external_event_id": external_event_id,
        "event_type": event_type,
        "source_ip": "192.0.2.100",
        "username": username,
        "outcome": outcome,
        "description": "Duplicate telemetry validation",
    }


def count_events():
    with get_connection() as connection:
        return connection.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()[0]


def count_alerts():
    with get_connection() as connection:
        return connection.execute(
            "SELECT COUNT(*) FROM security_alerts"
        ).fetchone()[0]


def test_retransmitted_event_is_not_inserted_twice(client):
    payload = make_payload("event-001")

    first = client.post("/api/v1/events", json=payload)
    second = client.post("/api/v1/events", json=payload)

    assert first.status_code == 201
    assert second.status_code == 200

    assert first.json()["event_id"] == second.json()["event_id"]
    assert second.json()["duplicate"] is True

    assert count_events() == 1


def test_distinct_event_ids_are_stored_separately(client):
    first = client.post(
        "/api/v1/events",
        json=make_payload("event-001"),
    )

    second = client.post(
        "/api/v1/events",
        json=make_payload("event-002"),
    )

    assert first.status_code == 201
    assert second.status_code == 201

    assert first.json()["event_id"] != second.json()["event_id"]
    assert count_events() == 2


def test_same_external_id_from_different_sources_is_not_a_duplicate(client):
    first = client.post(
        "/api/v1/events",
        json=make_payload(
            "event-001",
            source_system="firewall-a",
        ),
    )

    second = client.post(
        "/api/v1/events",
        json=make_payload(
            "event-001",
            source_system="endpoint-agent-b",
        ),
    )

    assert first.status_code == 201
    assert second.status_code == 201

    assert first.json()["event_id"] != second.json()["event_id"]
    assert count_events() == 2


def test_duplicate_brute_force_telemetry_does_not_inflate_threshold(client):
    payload = make_payload("auth-event-001")

    responses = [
        client.post("/api/v1/events", json=payload)
        for _ in range(5)
    ]

    assert all(
        response.status_code in (200, 201)
        for response in responses
    )

    assert count_events() == 1
    assert count_alerts() == 0

    assert all(
        response.json()["detection_count"] == 0
        for response in responses
    )


def test_distinct_authentication_events_still_trigger_brute_force(client):
    responses = [
        client.post(
            "/api/v1/events",
            json=make_payload(f"auth-event-{i}"),
        )
        for i in range(5)
    ]

    assert all(response.status_code == 201 for response in responses)

    assert count_events() == 5
    assert responses[-1].json()["detection_count"] >= 1
    assert count_alerts() >= 1


def test_duplicate_identifier_ignores_changed_payload(client):
    first = client.post(
        "/api/v1/events",
        json=make_payload(
            "event-001",
            username="administrator",
        ),
    )

    second = client.post(
        "/api/v1/events",
        json=make_payload(
            "event-001",
            username="different-user",
        ),
    )

    assert first.status_code == 201
    assert second.status_code == 200

    assert first.json()["event_id"] == second.json()["event_id"]
    assert second.json()["duplicate"] is True
    assert count_events() == 1
