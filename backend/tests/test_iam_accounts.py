from datetime import datetime, timedelta, timezone
import json
import sqlite3

import pytest

from app.iam.accounts import (
    activate_account, change_account_status, change_password, create_invitation,
)
from app.iam.exceptions import (
    AccountNotEligible, AccountNotFound, InvalidActivationToken,
    InvalidPassword, PasswordVerificationFailed,
)
from app.iam.migrations import apply_migrations
from app.iam.passwords import PasswordService

NOW = datetime(2026, 11, 12, 10, 0, tzinfo=timezone.utc)
NOW_ISO = NOW.isoformat()
PASSWORD = "correct horse battery staple"
NEW_PASSWORD = "another correct horse battery staple"


@pytest.fixture
def connection():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    apply_migrations(db, applied_at=NOW_ISO)
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def passwords():
    return PasswordService(memory_cost=1024, time_cost=1, parallelism=1)


def invite(connection, passwords, **kwargs):
    return create_invitation(
        connection, username=kwargs.pop("username", "analyst.one"),
        role=kwargs.pop("role", "analyst"), now=kwargs.pop("now", NOW),
        password_service=passwords, **kwargs,
    )


def active_account(connection, passwords):
    invitation = invite(connection, passwords)
    account = activate_account(
        connection, activation_token=invitation.activation_token,
        new_password=PASSWORD, now=NOW, password_service=passwords,
    )
    return invitation, account


def test_invitation_stores_only_argon2id_token_hash_and_creates_invited_account(
    connection, passwords
):
    invitation = invite(connection, passwords)
    row = connection.execute(
        """SELECT u.status, u.role, c.must_change_password, t.id AS token_id,
                  t.token_hash
           FROM iam_users u JOIN iam_credentials c ON c.user_id = u.id
           JOIN iam_activation_tokens t ON t.user_id = u.id WHERE u.id = ?""",
        (invitation.user_id,),
    ).fetchone()
    token_id, token_secret = invitation.activation_token.split(".", 1)
    assert row["status"] == "invited"
    assert row["role"] == "analyst"
    assert row["must_change_password"] == 1
    assert row["token_id"] == token_id
    assert row["token_hash"].startswith("$argon2id$")
    assert passwords.verify_password(row["token_hash"], token_secret)
    assert invitation.activation_token not in row["token_hash"]


def test_invitation_tokens_are_unique_and_high_entropy(connection, passwords):
    first = invite(connection, passwords)
    second = invite(connection, passwords, username="analyst.two")
    assert first.activation_token != second.activation_token
    assert len(first.activation_token) >= 40


def test_invitation_validates_role_lifetime_and_username(connection, passwords):
    with pytest.raises(ValueError, match="role"):
        invite(connection, passwords, role="administrator")
    with pytest.raises(ValueError, match="lifetime"):
        invite(connection, passwords, expires_in_seconds=30)
    with pytest.raises(ValueError, match="username"):
        invite(connection, passwords, username="ab")
    assert connection.execute("SELECT COUNT(*) FROM iam_users").fetchone()[0] == 0


def test_duplicate_normalized_username_rolls_back_invitation(connection, passwords):
    invite(connection, passwords)
    with pytest.raises(sqlite3.IntegrityError):
        invite(connection, passwords, username=" ANALYST.ONE ")
    assert connection.execute("SELECT COUNT(*) FROM iam_users").fetchone()[0] == 1
    assert connection.execute("SELECT COUNT(*) FROM iam_activation_tokens").fetchone()[0] == 1


def test_activation_sets_password_and_consumes_token_once(connection, passwords):
    invitation = invite(connection, passwords)
    account = activate_account(
        connection, activation_token=invitation.activation_token,
        new_password=PASSWORD, now=NOW + timedelta(minutes=1),
        password_service=passwords,
    )
    assert account["id"] == invitation.user_id
    assert account["status"] == "active"
    credential = connection.execute(
        "SELECT password_hash, must_change_password FROM iam_credentials WHERE user_id = ?",
        (invitation.user_id,),
    ).fetchone()
    assert passwords.verify_password(credential["password_hash"], PASSWORD)
    assert credential["must_change_password"] == 0
    consumed = connection.execute(
        "SELECT consumed_at FROM iam_activation_tokens WHERE user_id = ?",
        (invitation.user_id,),
    ).fetchone()["consumed_at"]
    assert consumed is not None


def test_activation_rejects_unknown_or_tampered_token(connection, passwords):
    invitation = invite(connection, passwords)
    with pytest.raises(InvalidActivationToken):
        activate_account(
            connection, activation_token=invitation.activation_token + "tampered",
            new_password=PASSWORD, now=NOW, password_service=passwords,
        )
    assert connection.execute(
        "SELECT status FROM iam_users WHERE id = ?", (invitation.user_id,)
    ).fetchone()["status"] == "invited"


def test_activation_rejects_wrong_selector_and_malformed_token(connection, passwords):
    invitation = invite(connection, passwords)
    _, token_secret = invitation.activation_token.split(".", 1)
    wrong_selector = "00000000-0000-4000-8000-000000000000"
    for supplied in (f"{wrong_selector}.{token_secret}", "not-a-token"):
        with pytest.raises(InvalidActivationToken):
            activate_account(
                connection, activation_token=supplied,
                new_password=PASSWORD, now=NOW, password_service=passwords,
            )
    assert connection.execute(
        "SELECT status FROM iam_users WHERE id = ?", (invitation.user_id,)
    ).fetchone()["status"] == "invited"


def test_activation_rejects_expired_token(connection, passwords):
    invitation = invite(connection, passwords, expires_in_seconds=60)
    with pytest.raises(InvalidActivationToken):
        activate_account(
            connection, activation_token=invitation.activation_token,
            new_password=PASSWORD, now=NOW + timedelta(seconds=60),
            password_service=passwords,
        )


def test_activation_rejects_replay(connection, passwords):
    invitation = invite(connection, passwords)
    activate_account(
        connection, activation_token=invitation.activation_token,
        new_password=PASSWORD, now=NOW, password_service=passwords,
    )
    with pytest.raises(InvalidActivationToken):
        activate_account(
            connection, activation_token=invitation.activation_token,
            new_password=NEW_PASSWORD, now=NOW + timedelta(seconds=1),
            password_service=passwords,
        )


def test_activation_policy_failure_does_not_consume_token(connection, passwords):
    invitation = invite(connection, passwords)
    with pytest.raises(InvalidPassword):
        activate_account(
            connection, activation_token=invitation.activation_token,
            new_password="too short", now=NOW, password_service=passwords,
        )
    assert connection.execute(
        "SELECT consumed_at FROM iam_activation_tokens WHERE user_id = ?",
        (invitation.user_id,),
    ).fetchone()["consumed_at"] is None


def test_activation_rejects_naive_datetime(connection, passwords):
    invitation = invite(connection, passwords)
    with pytest.raises(ValueError, match="timezone-aware"):
        activate_account(
            connection, activation_token=invitation.activation_token,
            new_password=PASSWORD, now=datetime(2026, 11, 12, 10, 0),
            password_service=passwords,
        )


def test_security_events_never_contain_raw_activation_token(connection, passwords):
    invitation = invite(connection, passwords)
    activate_account(
        connection, activation_token=invitation.activation_token,
        new_password=PASSWORD, now=NOW, password_service=passwords,
    )
    events = [
        json.loads(row[0]) for row in connection.execute(
            "SELECT metadata_json FROM iam_security_events"
        )
    ]
    assert all(invitation.activation_token not in json.dumps(event) for event in events)


def test_password_change_updates_hash(connection, passwords):
    invitation, account = active_account(connection, passwords)
    change_password(
        connection, user_id=account["id"], current_password=PASSWORD,
        new_password=NEW_PASSWORD, now=NOW + timedelta(minutes=1),
        password_service=passwords,
    )
    stored = connection.execute(
        "SELECT password_hash, must_change_password FROM iam_credentials WHERE user_id = ?",
        (invitation.user_id,),
    ).fetchone()
    assert passwords.verify_password(stored["password_hash"], NEW_PASSWORD)
    assert stored["must_change_password"] == 0


def test_password_change_rejects_wrong_current_password(connection, passwords):
    _, account = active_account(connection, passwords)
    with pytest.raises(PasswordVerificationFailed):
        change_password(
            connection, user_id=account["id"],
            current_password="incorrect current passphrase",
            new_password=NEW_PASSWORD, now=NOW, password_service=passwords,
        )


def test_password_change_rejects_reusing_current_password(connection, passwords):
    _, account = active_account(connection, passwords)
    with pytest.raises(InvalidPassword, match="differ"):
        change_password(
            connection, user_id=account["id"], current_password=PASSWORD,
            new_password=PASSWORD, now=NOW, password_service=passwords,
        )


def insert_session(connection, user_id, session_id):
    connection.execute(
        """INSERT INTO iam_sessions
           (id, user_id, session_hash, created_at, last_seen_at,
            idle_expires_at, absolute_expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (session_id, user_id, session_id.replace("-", "") * 2,
         NOW_ISO, NOW_ISO, (NOW + timedelta(hours=1)).isoformat(),
         (NOW + timedelta(hours=8)).isoformat()),
    )


def test_password_change_revokes_all_existing_sessions(connection, passwords):
    invitation, account = active_account(connection, passwords)
    insert_session(connection, invitation.user_id, "12345678-1234-4234-8234-123456789012")
    change_password(
        connection, user_id=account["id"], current_password=PASSWORD,
        new_password=NEW_PASSWORD, now=NOW + timedelta(minutes=1),
        password_service=passwords,
    )
    revoked = connection.execute(
        "SELECT revoked_at FROM iam_sessions WHERE user_id = ?", (invitation.user_id,)
    ).fetchone()["revoked_at"]
    assert revoked is not None


@pytest.mark.parametrize("status", ["disabled", "locked"])
def test_disabling_or_locking_revokes_sessions(connection, passwords, status):
    invitation, account = active_account(connection, passwords)
    insert_session(connection, invitation.user_id, "22345678-1234-4234-8234-123456789012")
    changed = change_account_status(
        connection, user_id=account["id"], status=status,
        now=NOW + timedelta(minutes=1),
    )
    assert changed["status"] == status
    assert connection.execute(
        "SELECT revoked_at FROM iam_sessions WHERE user_id = ?", (invitation.user_id,)
    ).fetchone()["revoked_at"] is not None


def test_status_service_cannot_activate_or_accept_unknown_status(connection, passwords):
    invitation = invite(connection, passwords)
    with pytest.raises(ValueError, match="disabled or locked"):
        change_account_status(
            connection, user_id=invitation.user_id, status="active", now=NOW
        )
    with pytest.raises(ValueError):
        change_account_status(
            connection, user_id=invitation.user_id, status="unknown", now=NOW
        )


def test_disabled_account_cannot_change_password(connection, passwords):
    _, account = active_account(connection, passwords)
    change_account_status(
        connection, user_id=account["id"], status="disabled", now=NOW
    )
    with pytest.raises(AccountNotEligible):
        change_password(
            connection, user_id=account["id"], current_password=PASSWORD,
            new_password=NEW_PASSWORD, now=NOW, password_service=passwords,
        )


def test_status_change_rejects_unknown_user(connection):
    with pytest.raises(AccountNotFound):
        change_account_status(
            connection, user_id="12345678-1234-4234-8234-123456789012",
            status="disabled", now=NOW,
        )
