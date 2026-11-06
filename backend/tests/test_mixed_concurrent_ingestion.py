from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from app.database import get_connection


def count_events():
    with get_connection() as connection:
        return connection.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()[0]


def test_mixed_duplicate_and_distinct_events_concurrently(client):
    repeated_payloads = [
        {
            "source_system": "mixed-concurrency-agent",
            "external_event_id": f"repeated-event-{index:03d}",
            "event_type": "heartbeat",
            "description": f"Repeated event {index}",
        }
        for index in range(5)
    ]

    distinct_payloads = [
        {
            "source_system": "mixed-concurrency-agent",
            "external_event_id": f"distinct-event-{index:03d}",
            "event_type": "heartbeat",
            "description": f"Distinct event {index}",
        }
        for index in range(5)
    ]

    # Submit each repeated event four times.
    workload = [
        payload.copy()
        for payload in repeated_payloads
        for _ in range(4)
    ]

    # Add five events that each have a unique identity.
    workload.extend(distinct_payloads)

    with ThreadPoolExecutor(max_workers=10) as executor:
        responses = list(
            executor.map(
                lambda payload: client.post(
                    "/api/v1/events",
                    json=payload,
                ),
                workload,
            )
        )

    assert all(
        response.status_code in (200, 201)
        for response in responses
    )

    results = [
        (payload, response)
        for payload, response in zip(workload, responses)
    ]

    grouped_results = {}

    for payload, response in results:
        external_id = payload["external_event_id"]

        grouped_results.setdefault(external_id, []).append(
            response.json()
        )

    # Every repeated identity must produce one stored event.
    for payload in repeated_payloads:
        external_id = payload["external_event_id"]
        group = grouped_results[external_id]

        assert len(group) == 4
        assert sum(
            result["duplicate"] is False
            for result in group
        ) == 1
        assert sum(
            result["duplicate"] is True
            for result in group
        ) == 3

        assert len({
            result["event_id"]
            for result in group
        }) == 1

    # Every distinct identity must be stored independently.
    for payload in distinct_payloads:
        external_id = payload["external_event_id"]
        group = grouped_results[external_id]

        assert len(group) == 1
        assert group[0]["duplicate"] is False
        assert group[0]["event_id"]

    # Five repeated identities plus five distinct identities.
    assert count_events() == 10

    assert sum(
        response.status_code == 201
        for response in responses
    ) == 10

    assert sum(
        response.status_code == 200
        for response in responses
    ) == 10
