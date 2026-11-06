from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

from app.database import get_connection


def test_database_integrity_after_concurrent_event_ingestion(
    client,
    isolated_database,
    seeded_alert,
    seeded_event,
    seeded_correlation,
):
    requests = []

    repeated_identities = [
        f"integrity-repeated-{index}"
        for index in range(5)
    ]

    distinct_identities = [
        f"integrity-distinct-{index}"
        for index in range(5)
    ]

    # Submit each repeated identity four times.
    for external_event_id in repeated_identities:
        for _ in range(4):
            requests.append({
                "source_system": "integrity-test-agent",
                "external_event_id": external_event_id,
                "event_type": "heartbeat",
                "description": "Concurrent integrity test",
            })

    # Submit five additional unique events.
    for external_event_id in distinct_identities:
        requests.append({
            "source_system": "integrity-test-agent",
            "external_event_id": external_event_id,
            "event_type": "heartbeat",
            "description": "Distinct integrity test",
        })

    # Execute all 25 requests concurrently.
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [
            executor.submit(
                client.post,
                "/api/v1/events",
                json=payload,
            )
            for payload in requests
        ]

        responses = [
            future.result(timeout=15)
            for future in futures
        ]

    # --------------------------------------------------
    # 1. VERIFY API RESPONSES
    # --------------------------------------------------

    assert len(responses) == 25

    assert all(
        response.status_code in (200, 201)
        for response in responses
    )

    created_responses = [
        response
        for response in responses
        if response.status_code == 201
    ]

    duplicate_responses = [
        response
        for response in responses
        if response.status_code == 200
    ]

    assert len(created_responses) == 10
    assert len(duplicate_responses) == 15

    # --------------------------------------------------
    # 2. VERIFY EVENT ID UNIQUENESS
    # --------------------------------------------------

    event_ids = [
        response.json()["event_id"]
        for response in responses
    ]

    assert len(set(event_ids)) == 10

    # --------------------------------------------------
    # 3. VERIFY IDEMPOTENCY
    # --------------------------------------------------

    grouped_results = defaultdict(list)

    for payload, response in zip(requests, responses):
        result = response.json()

        grouped_results[
            payload["external_event_id"]
        ].append(result)

    for external_event_id in repeated_identities:
        results = grouped_results[external_event_id]

        assert len(results) == 4

        assert sum(
            result["duplicate"] is False
            for result in results
        ) == 1

        assert sum(
            result["duplicate"] is True
            for result in results
        ) == 3

        assert len({
            result["event_id"]
            for result in results
        }) == 1

    for external_event_id in distinct_identities:
        results = grouped_results[external_event_id]

        assert len(results) == 1
        assert results[0]["duplicate"] is False

    # --------------------------------------------------
    # 4. VERIFY DATABASE INTEGRITY
    # --------------------------------------------------

    with get_connection() as connection:

        integrity_result = connection.execute(
            "PRAGMA integrity_check"
        ).fetchone()[0]

        assert integrity_result == "ok"

        foreign_key_errors = connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()

        assert foreign_key_errors == []

        # Ten new events plus the existing seeded event.
        total_events = connection.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()[0]

        assert total_events == 11

        # All event primary keys must remain unique.
        event_id_count = connection.execute(
            """
            SELECT COUNT(DISTINCT id)
            FROM security_events
            """
        ).fetchone()[0]

        assert event_id_count == total_events

        # Every submitted external identity must exist once.
        identity_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM security_events
            WHERE source_system = ?
            """,
            ("integrity-test-agent",),
        ).fetchone()[0]

        assert identity_count == 10

        # Confirm there are no duplicate external identities.
        duplicate_identity_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM (
                SELECT source_system, external_event_id
                FROM security_events
                WHERE source_system = ?
                GROUP BY source_system, external_event_id
                HAVING COUNT(*) > 1
            )
            """,
            ("integrity-test-agent",),
        ).fetchone()[0]

        assert duplicate_identity_count == 0

        # --------------------------------------------------
        # 5. VERIFY EXISTING RELATIONSHIPS SURVIVED
        # --------------------------------------------------

        existing_event = connection.execute(
            """
            SELECT id
            FROM security_events
            WHERE id = ?
            """,
            (seeded_event,),
        ).fetchone()

        existing_alert = connection.execute(
            """
            SELECT id
            FROM security_alerts
            WHERE id = ?
            """,
            (seeded_alert,),
        ).fetchone()

        existing_correlation = connection.execute(
            """
            SELECT id
            FROM security_correlations
            WHERE id = ?
            """,
            (seeded_correlation,),
        ).fetchone()

        assert existing_event is not None
        assert existing_alert is not None
        assert existing_correlation is not None

        existing_relationship = connection.execute(
            """
            SELECT correlation_id, alert_id
            FROM security_correlation_alerts
            WHERE correlation_id = ?
            AND alert_id = ?
            """,
            (seeded_correlation, seeded_alert),
        ).fetchone()

        assert existing_relationship is not None
