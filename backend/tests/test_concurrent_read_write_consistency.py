from concurrent.futures import ThreadPoolExecutor

from app.database import get_connection


def test_concurrent_event_reads_and_writes_remain_consistent(
    client,
    isolated_database,
):
    event_count = 30
    read_count = 10

    payloads = [
        {
            "source_system": "read-write-test-agent",
            "external_event_id": f"read-write-event-{index}",
            "event_type": "heartbeat",
            "description": f"Concurrent read/write test event {index}",
        }
        for index in range(event_count)
    ]

    with ThreadPoolExecutor(max_workers=20) as executor:

        write_futures = [
            executor.submit(
                client.post,
                "/api/v1/events",
                json=payload,
            )
            for payload in payloads
        ]

        read_futures = [
            executor.submit(
                client.get,
                "/api/v1/events",
                params={"limit": 1000},
            )
            for _ in range(read_count)
        ]

        write_responses = [
            future.result(timeout=20)
            for future in write_futures
        ]

        read_responses = [
            future.result(timeout=20)
            for future in read_futures
        ]

    # --------------------------------------------------
    # 1. VERIFY ALL WRITES SUCCEEDED
    # --------------------------------------------------

    assert len(write_responses) == event_count

    assert all(
        response.status_code == 201
        for response in write_responses
    )

    written_event_ids = {
        response.json()["event_id"]
        for response in write_responses
    }

    assert len(written_event_ids) == event_count

    assert all(
        response.json()["duplicate"] is False
        for response in write_responses
    )

    # --------------------------------------------------
    # 2. VERIFY ALL READS RETURNED VALID RESPONSES
    # --------------------------------------------------

    assert len(read_responses) == read_count

    for response in read_responses:
        assert response.status_code == 200

        result = response.json()

        assert "count" in result
        assert "events" in result

        assert result["count"] == len(result["events"])

        for event in result["events"]:
            assert event["id"] is not None
            assert event["event_type"]
            assert event["occurred_at"]
            assert event["received_at"]

    # --------------------------------------------------
    # 3. VERIFY FINAL DATABASE STATE
    # --------------------------------------------------

    with get_connection() as connection:

        total_events = connection.execute(
            """
            SELECT COUNT(*)
            FROM security_events
            """
        ).fetchone()[0]

        test_events = connection.execute(
            """
            SELECT id, external_event_id
            FROM security_events
            WHERE source_system = ?
            """,
            ("read-write-test-agent",),
        ).fetchall()

        integrity_result = connection.execute(
            "PRAGMA integrity_check"
        ).fetchone()[0]

        foreign_key_errors = connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()

    assert total_events == event_count
    assert len(test_events) == event_count

    persisted_event_ids = {
        row["id"]
        for row in test_events
    }

    assert persisted_event_ids == written_event_ids

    assert integrity_result == "ok"
    assert foreign_key_errors == []

    # --------------------------------------------------
    # 4. VERIFY ALL EXTERNAL IDENTITIES ARE UNIQUE
    # --------------------------------------------------

    with get_connection() as connection:
        duplicate_count = connection.execute(
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
            ("read-write-test-agent",),
        ).fetchone()[0]

    assert duplicate_count == 0
