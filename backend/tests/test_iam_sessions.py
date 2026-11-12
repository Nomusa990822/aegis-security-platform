from datetime import datetime, timedelta, timezone
import sqlite3

import pytest

from app.iam.accounts import activate_account, create_invitation
from app.iam.migrations import apply_migrations
from app.iam.passwords import PasswordService
from app.iam.sessions import (
    issue_session, purge_expired_sessions, revoke_all_user_sessions,
    revoke_session, validate_session,
)

NOW = datetime(2026, 11, 12, 10, 0, tzinfo=timezone.utc)
NOW_ISO = NOW.isoformat()
PASSWORDS = PasswordService(memory_cost=1024, time_cost=1, parallelism=1)


@pytest.fixture
def connection():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    assert apply_migrations(db, applied_at=NOW_ISO) == [1, 2]
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def active_user(connection):
    invitation = create_invitation(
        connection, username="session.user", role="analyst",
        now=NOW, password_service=PASSWORDS,
    )
    activate_account(
        connection, activation_token=invitation.activation_token,
        new_password="correct horse battery staple", now=NOW,
        password_service=PASSWORDS,
    )
    return invitation.user_id


def test_issue_stores_only_hash_and_never_marks_mfa_verified(connection, active_user):
    issued = issue_session(connection, user_id=active_user, now=NOW)
    row = connection.execute(
        "SELECT session_hash, mfa_verified_at FROM iam_sessions WHERE id = ?",
        (issued.session_id,),
    ).fetchone()
    assert row["session_hash"] != issued.token
    assert len(row["session_hash"]) == 64
    assert row["mfa_verified_at"] is None
    assert issued.mfa_verified_at is None
    assert issued.absolute_expires_at > issued.idle_expires_at


def test_issue_rejects_inactive_or_unknown_user(connection):
    with pytest.raises(ValueError, match="active"):
        issue_session(connection, user_id="00000000-0000-4000-8000-000000000000", now=NOW)


def test_issue_validates_lifetimes(connection, active_user):
    with pytest.raises(ValueError):
        issue_session(connection, user_id=active_user, now=NOW, idle_ttl_seconds=3600, absolute_ttl_seconds=1800)
    with pytest.raises(ValueError):
        issue_session(connection, user_id=active_user, now=NOW, absolute_ttl_seconds=30)


def test_validate_renews_idle_expiry_but_never_absolute_expiry(connection, active_user):
    issued = issue_session(
        connection, user_id=active_user, now=NOW,
        idle_ttl_seconds=300, absolute_ttl_seconds=3600,
    )
    validated = validate_session(
        connection, token=issued.token, now=NOW + timedelta(minutes=2),
        idle_ttl_seconds=300,
    )
    assert validated is not None
    assert validated.last_seen_at == (NOW + timedelta(minutes=2)).isoformat(timespec="microseconds")
    assert validated.idle_expires_at == (NOW + timedelta(minutes=7)).isoformat(timespec="microseconds")
    assert validated.absolute_expires_at == issued.absolute_expires_at
    assert validated.mfa_verified_at is None


def test_idle_expiry_is_enforced(connection, active_user):
    issued = issue_session(
        connection, user_id=active_user, now=NOW,
        idle_ttl_seconds=60, absolute_ttl_seconds=3600,
    )
    assert validate_session(
        connection, token=issued.token, now=NOW + timedelta(seconds=60)
    ) is None


def test_absolute_expiry_is_enforced_even_if_idle_window_was_renewed(connection, active_user):
    issued = issue_session(
        connection, user_id=active_user, now=NOW,
        idle_ttl_seconds=300, absolute_ttl_seconds=600,
    )
    assert validate_session(
        connection, token=issued.token, now=NOW + timedelta(seconds=299),
        idle_ttl_seconds=300,
    ) is not None
    assert validate_session(
        connection, token=issued.token, now=NOW + timedelta(seconds=598),
        idle_ttl_seconds=300,
    ) is not None
    assert validate_session(
        connection, token=issued.token, now=NOW + timedelta(seconds=600)
    ) is None


def test_revocation_is_idempotent_and_invalidates_session(connection, active_user):
    issued = issue_session(connection, user_id=active_user, now=NOW)
    assert revoke_session(connection, token=issued.token, now=NOW + timedelta(seconds=1))
    assert not revoke_session(connection, token=issued.token, now=NOW + timedelta(seconds=2))
    assert validate_session(
        connection, token=issued.token, now=NOW + timedelta(seconds=3)
    ) is None


def test_user_wide_revocation(connection, active_user):
    first = issue_session(connection, user_id=active_user, now=NOW)
    second = issue_session(connection, user_id=active_user, now=NOW)
    assert revoke_all_user_sessions(
        connection, user_id=active_user, now=NOW + timedelta(seconds=1)
    ) == 2
    assert validate_session(connection, token=first.token, now=NOW + timedelta(seconds=2)) is None
    assert validate_session(connection, token=second.token, now=NOW + timedelta(seconds=2)) is None


def test_disabled_account_invalidates_session(connection, active_user):
    issued = issue_session(connection, user_id=active_user, now=NOW)
    connection.execute(
        "UPDATE iam_users SET status = 'disabled' WHERE id = ?", (active_user,)
    )
    assert validate_session(connection, token=issued.token, now=NOW + timedelta(seconds=1)) is None


def test_malformed_tokens_fail_closed(connection):
    assert validate_session(connection, token="not-a-session", now=NOW) is None
    assert not revoke_session(connection, token="not-a-session", now=NOW)


def test_session_cleanup_respects_retention(connection, active_user):
    issued = issue_session(connection, user_id=active_user, now=NOW)
    revoke_session(connection, token=issued.token, now=NOW + timedelta(seconds=1))
    assert purge_expired_sessions(
        connection, now=NOW + timedelta(days=1), retention_seconds=0
    ) == 1
    assert connection.execute(
        "SELECT COUNT(*) FROM iam_sessions WHERE id = ?", (issued.session_id,)
    ).fetchone()[0] == 0


def test_session_time_must_be_timezone_aware(connection, active_user):
    with pytest.raises(ValueError, match="timezone-aware"):
        issue_session(connection, user_id=active_user, now=datetime(2026, 11, 12, 10, 0))
