from datetime import datetime, timedelta, timezone
import sqlite3

import pytest

from app.iam.auth_throttling import (
    authentication_succeeded, is_authentication_blocked,
    purge_authentication_throttles, record_authentication_failure,
)
from app.iam.migrations import apply_migrations

NOW = datetime(2026, 11, 12, 10, 0, tzinfo=timezone.utc)
SECRET = "a-throttling-hmac-key-with-at-least-32-bytes"


@pytest.fixture
def connection():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    apply_migrations(db, applied_at=NOW.isoformat())
    try:
        yield db
    finally:
        db.close()


def record(connection, **kwargs):
    return record_authentication_failure(
        connection, scope="login-user", identifier="analyst.one",
        secret=SECRET, now=NOW, max_failures=3,
        window_seconds=300, lockout_seconds=120, **kwargs,
    )


def test_persistent_bucket_blocks_at_threshold_and_reports_retry(connection):
    assert record(connection).allowed
    assert record(connection).allowed
    blocked = record(connection)
    assert not blocked.allowed
    assert blocked.failures == 3
    assert blocked.retry_after_seconds == 120
    audit = connection.execute(
        "SELECT event_type, success, metadata_json FROM iam_security_events"
    ).fetchone()
    assert audit["event_type"] == "authentication_throttled"
    assert audit["success"] == 0
    assert "analyst.one" not in audit["metadata_json"]
    state = is_authentication_blocked(
        connection, scope="login-user", identifier="analyst.one",
        secret=SECRET, now=NOW + timedelta(seconds=1),
    )
    assert not state.allowed
    assert state.retry_after_seconds == 119


def test_block_expires_and_new_failure_window_can_start(connection):
    record(connection)
    record(connection)
    record(connection)
    next_window = NOW + timedelta(seconds=301)
    state = is_authentication_blocked(
        connection, scope="login-user", identifier="analyst.one",
        secret=SECRET, now=next_window,
    )
    assert state.allowed
    fresh = record_authentication_failure(
        connection, scope="login-user", identifier="analyst.one",
        secret=SECRET, now=next_window, max_failures=3,
        window_seconds=300, lockout_seconds=120,
    )
    assert fresh.allowed and fresh.failures == 1


def test_success_clears_only_matching_bucket(connection):
    record(connection)
    record_authentication_failure(
        connection, scope="login-ip", identifier="192.0.2.5",
        secret=SECRET, now=NOW,
    )
    assert authentication_succeeded(
        connection, scope="login-user", identifier="analyst.one", secret=SECRET
    )
    assert is_authentication_blocked(
        connection, scope="login-user", identifier="analyst.one",
        secret=SECRET, now=NOW,
    ).allowed
    assert is_authentication_blocked(
        connection, scope="login-ip", identifier="192.0.2.5",
        secret=SECRET, now=NOW,
    ).failures == 1


def test_identifiers_are_not_stored_in_plaintext(connection):
    record(connection)
    rows = connection.execute(
        "SELECT bucket_hash, scope FROM iam_auth_rate_limits"
    ).fetchall()
    assert len(rows) == 1
    assert rows[0]["bucket_hash"] != "analyst.one"
    assert len(rows[0]["bucket_hash"]) == 64
    assert connection.execute(
        "SELECT COUNT(*) FROM iam_auth_rate_limits WHERE bucket_hash = ?",
        ("analyst.one",),
    ).fetchone()[0] == 0


def test_invalid_secrets_and_settings_are_rejected(connection):
    with pytest.raises(ValueError, match="32 bytes"):
        record_authentication_failure(
            connection, scope="login", identifier="user", secret="short", now=NOW
        )
    with pytest.raises(ValueError, match="positive"):
        record_authentication_failure(
            connection, scope="login", identifier="user", secret=SECRET,
            now=NOW, max_failures=0,
        )
    with pytest.raises(ValueError, match="scope label"):
        record_authentication_failure(
            connection, scope="analyst.one", identifier="user",
            secret=SECRET, now=NOW,
        )


def test_purge_removes_old_fingerprints(connection):
    record(connection)
    assert purge_authentication_throttles(
        connection, now=NOW + timedelta(days=2), retention_seconds=86400
    ) == 1
