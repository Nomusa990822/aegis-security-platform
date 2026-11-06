
from concurrent.futures import ThreadPoolExecutor

from app.database import get_connection


def count_events():
    with get_connection() as connection:
        return connection.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()[0]


def test_simultaneous_retransmissions_create_only_one_event(client):
    payload = {
        "source_system": "concurrency-test-agent",
        "external_event_id": "concurrent-event-001",
        "event_type": "heartbeat",
        "description": "Concurrent idempotency validation",
    }

    request_count = 20

    with ThreadPoolExecutor(max_workers=10) as executor:
        responses = list(
            executor.map(
                lambda _: client.post(
                    "/api/v1/events",
                    json=payload,
                ),
                range(request_count),
            )
        )

    assert all(
        response.status_code in (200, 201)
        for response in responses
    )

    assert sum(
        response.status_code == 201
        for response in responses
    ) == 1

    assert sum(
        response.status_code == 200
        for response in responses
    ) == request_count - 1

    event_ids = {
        response.json()["event_id"]
        for response in responses
    }

    assert len(event_ids) == 1
    assert count_events() == 1

    assert sum(
        response.json()["duplicate"] is True
        for response in responses
    ) == request_count - 1
