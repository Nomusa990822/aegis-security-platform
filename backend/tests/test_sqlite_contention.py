
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from app.database import get_connection


def insert_test_event(started):
    connection = get_connection()

    try:
        started.set()

        cursor = connection.execute(
            """
            INSERT INTO security_events (
                event_type,
                description,
                occurred_at,
                received_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                "heartbeat",
                "SQLite contention recovery test",
                "2026-11-06T10:00:00+00:00",
                "2026-11-06T10:00:00+00:00",
            ),
        )

        connection.commit()
        return cursor.lastrowid

    finally:
        connection.close()


def count_events():
    connection = get_connection()

    try:
        return connection.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()[0]

    finally:
        connection.close()


def run_contention_test(release_transaction):
    lock_connection = get_connection()

    executor = ThreadPoolExecutor(max_workers=1)

    try:
        lock_connection.execute("BEGIN IMMEDIATE")

        started = threading.Event()

        future = executor.submit(
            insert_test_event,
            started,
        )

        assert started.wait(timeout=2)

        # Give the worker time to encounter the write lock.
        time.sleep(0.2)

        assert not future.done()

        release_transaction(lock_connection)

        event_id = future.result(timeout=5)

        assert event_id is not None
        assert count_events() == 1

    finally:
        if lock_connection.in_transaction:
            lock_connection.rollback()

        lock_connection.close()
        executor.shutdown(wait=True)


def test_write_recovers_after_blocking_transaction_commits(
    isolated_database,
):
    run_contention_test(
        lambda connection: connection.commit()
    )


def test_write_recovers_after_blocking_transaction_rolls_back(
    isolated_database,
):
    run_contention_test(
        lambda connection: connection.rollback()
    )
