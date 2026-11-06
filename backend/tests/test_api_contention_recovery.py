import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.database import get_connection


@pytest.mark.parametrize(
    "release_action",
    ["commit", "rollback"],
)
def test_event_ingestion_recovers_after_database_lock(
    client,
    isolated_database,
    release_action,
):
    lock_connection = get_connection()

    executor = ThreadPoolExecutor(max_workers=1)

    try:
        lock_connection.execute("BEGIN IMMEDIATE")

        started = threading.Event()

        payload = {
            "source_system": "contention-recovery-agent",
            "external_event_id": f"recovery-{release_action}",
            "event_type": "heartbeat",
            "description": "API contention recovery test",
        }

        def submit_event():
            started.set()

            return client.post(
                "/api/v1/events",
                json=payload,
            )

        future = executor.submit(submit_event)

        assert started.wait(timeout=2)

        time.sleep(0.2)

        # The request should be waiting for the SQLite write lock.
        assert not future.done()

        if release_action == "commit":
            lock_connection.commit()
        else:
            lock_connection.rollback()

        response = future.result(timeout=5)

        assert response.status_code == 201

        result = response.json()

        assert result["duplicate"] is False
        assert result["event_id"] is not None

        with get_connection() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM security_events
                WHERE source_system = ?
                AND external_event_id = ?
                """,
                (
                    payload["source_system"],
                    payload["external_event_id"],
                ),
            ).fetchall()

        assert len(rows) == 1

    finally:
        if lock_connection.in_transaction:
            lock_connection.rollback()

        lock_connection.close()
        executor.shutdown(wait=True)
