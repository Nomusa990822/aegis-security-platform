
from concurrent.futures import ThreadPoolExecutor

from app.database import get_connection


def count_events():
    with get_connection() as connection:
        return connection.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()[0]


def test_simultaneous_distinct_events_are_all_stored(client):
    request_count = 20

    payloads = [
        {
            "source_system": "concurrency-test-agent",
            "external_event_id": f"unique-event-{index:03d}",
            "event_type": "heartbeat",
            "description": f"Concurrent distinct event {index}",
        }
        for index in range(request_count)
    ]

    with ThreadPoolExecutor(max_workers=10) as executor:
        responses = list(
            executor.map(
                lambda payload: client.post(
                    "/api/v1/events",
                    json=payload,
                ),
                payloads,
            )
        )

    assert all(
        response.status_code == 201
        for response in responses
    )

    event_ids = {
        response.json()["event_id"]
        for response in responses
    }

    assert len(event_ids) == request_count

    assert all(
        response.json()["duplicate"] is False
        for response in responses
    )

    assert count_events() == request_count
