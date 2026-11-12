"""Local IAM invitation, activation, password-change, and status services.

These functions are service primitives, not public HTTP endpoints. Callers
must enforce operator authorization before issuing invitations or changing
account status. Route integration and interactive authentication are separate
milestones.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import secrets
import sqlite3
import uuid

from app.iam import repository
from app.iam.exceptions import (
    AccountNotEligible, AccountNotFound, InvalidActivationToken,
    InvalidPassword, PasswordVerificationFailed,
)
from app.iam.passwords import DEFAULT_PASSWORD_SERVICE, PasswordService
from app.iam.security_events import record_security_event

MIN_ACTIVATION_TTL_SECONDS = 60
MAX_ACTIVATION_TTL_SECONDS = 7 * 24 * 60 * 60


@dataclass(frozen=True)
class AccountInvitation:
    """One-time invitation result; the raw activation token is returned once."""
    user_id: str
    username: str
    role: str
    activation_token: str
    expires_at: str


def _timestamp(now: datetime | None) -> datetime:
    value = datetime.now(timezone.utc) if now is None else now
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("now must be a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="microseconds")


def _public_account(row: sqlite3.Row) -> dict[str, str | None]:
    return {
        "id": row["id"], "username": row["username"], "role": row["role"],
        "status": row["status"], "activated_at": row["activated_at"],
    }


def create_invitation(
    connection: sqlite3.Connection, *, username: str, role: str,
    now: datetime | None = None, expires_in_seconds: int = 24 * 60 * 60,
    password_service: PasswordService = DEFAULT_PASSWORD_SERVICE,
) -> AccountInvitation:
    """Create an invited account and hash-only, high-entropy activation token."""
    if (
        isinstance(expires_in_seconds, bool)
        or not isinstance(expires_in_seconds, int)
        or not MIN_ACTIVATION_TTL_SECONDS <= expires_in_seconds <= MAX_ACTIVATION_TTL_SECONDS
    ):
        raise ValueError("activation lifetime must be between 60 seconds and 7 days")
    normalized_username = repository.normalize_username(username)
    if role not in {"analyst", "approver"}:
        raise ValueError("role must be analyst or approver")

    created = _timestamp(now)
    created_at = _iso(created)
    expires_at = _iso(created + timedelta(seconds=expires_in_seconds))
    user_id = str(uuid.uuid4())
    token_id = str(uuid.uuid4())
    raw_secret = secrets.token_urlsafe(32)
    # The public selector permits an indexed lookup; the secret remains
    # protected by Argon2id, just like a user password.
    raw_token = f"{token_id}.{raw_secret}"
    token_hash = password_service.hash_password(raw_secret)
    # Invited accounts cannot authenticate. This undisclosed random value is
    # replaced when the recipient chooses a password during activation.
    placeholder_hash = password_service.hash_password(secrets.token_urlsafe(48))

    savepoint = "iam_create_invitation"
    connection.execute(f"SAVEPOINT {savepoint}")
    try:
        repository.create_account(
            connection, user_id=user_id, username=username.strip(), role=role,
            password_hash=placeholder_hash, created_at=created_at,
        )
        connection.execute(
            """INSERT INTO iam_activation_tokens
               (id, user_id, token_hash, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?)""",
            (token_id, user_id, token_hash, created_at, expires_at),
        )
        record_security_event(
            connection, event_type="account_invited", user_id=user_id,
            occurred_at=created_at, success=True,
            metadata={"role": role, "username": normalized_username},
        )
        connection.execute(f"RELEASE SAVEPOINT {savepoint}")
    except Exception:
        connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
        connection.execute(f"RELEASE SAVEPOINT {savepoint}")
        raise

    return AccountInvitation(user_id, username.strip(), role, raw_token, expires_at)


def activate_account(
    connection: sqlite3.Connection, *, activation_token: str, new_password: str,
    now: datetime | None = None,
    password_service: PasswordService = DEFAULT_PASSWORD_SERVICE,
) -> dict[str, str | None]:
    """Consume a valid invitation once and set the recipient's password."""
    if not isinstance(activation_token, str) or not 70 <= len(activation_token) <= 300:
        raise InvalidActivationToken("activation token is invalid or expired")
    try:
        token_id, token_secret = activation_token.split(".", 1)
        if str(uuid.UUID(token_id)) != token_id:
            raise ValueError("non-canonical token selector")
    except (ValueError, TypeError, AttributeError) as exc:
        raise InvalidActivationToken("activation token is invalid or expired") from exc
    if not 32 <= len(token_secret) <= 256:
        raise InvalidActivationToken("activation token is invalid or expired")

    current_at = _iso(_timestamp(now))
    invitation = connection.execute(
        """SELECT t.id AS token_id, t.user_id, t.token_hash, t.expires_at,
                  t.consumed_at, u.role, u.status
           FROM iam_activation_tokens AS t
           JOIN iam_users AS u ON u.id = t.user_id
           WHERE t.id = ?""",
        (token_id,),
    ).fetchone()
    if (
        invitation is None or invitation["consumed_at"] is not None
        or invitation["expires_at"] <= current_at or invitation["status"] != "invited"
        or not password_service.verify_password(invitation["token_hash"], token_secret)
    ):
        raise InvalidActivationToken("activation token is invalid or expired")

    new_hash = password_service.hash_password(new_password)
    savepoint = "iam_activate_account"
    connection.execute(f"SAVEPOINT {savepoint}")
    try:
        token_update = connection.execute(
            """UPDATE iam_activation_tokens SET consumed_at = ?
               WHERE id = ? AND consumed_at IS NULL AND expires_at > ?""",
            (current_at, invitation["token_id"], current_at),
        )
        if token_update.rowcount != 1:
            raise InvalidActivationToken("activation token is invalid or expired")
        user_update = connection.execute(
            """UPDATE iam_users SET status = 'active', activated_at = ?, updated_at = ?
               WHERE id = ? AND status = 'invited'""",
            (current_at, current_at, invitation["user_id"]),
        )
        if user_update.rowcount != 1:
            raise AccountNotEligible("account is not eligible for activation")
        credential_update = connection.execute(
            """UPDATE iam_credentials
               SET password_hash = ?, password_changed_at = ?, must_change_password = 0
               WHERE user_id = ?""",
            (new_hash, current_at, invitation["user_id"]),
        )
        if credential_update.rowcount != 1:
            raise AccountNotEligible("account credentials are unavailable")
        record_security_event(
            connection, event_type="account_activated",
            user_id=invitation["user_id"], occurred_at=current_at, success=True,
            metadata={"role": invitation["role"]},
        )
        connection.execute(f"RELEASE SAVEPOINT {savepoint}")
    except Exception:
        connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
        connection.execute(f"RELEASE SAVEPOINT {savepoint}")
        raise

    row = repository.get_account_by_id(connection, invitation["user_id"])
    if row is None:
        raise AccountNotFound("account does not exist")
    return _public_account(row)


def change_password(
    connection: sqlite3.Connection, *, user_id: str, current_password: str,
    new_password: str, now: datetime | None = None,
    password_service: PasswordService = DEFAULT_PASSWORD_SERVICE,
) -> None:
    """Change an active user's password and revoke all existing IAM sessions."""
    current_at = _iso(_timestamp(now))
    account = repository.get_account_by_id(connection, user_id)
    if account is None:
        raise AccountNotFound("account does not exist")
    if account["status"] != "active":
        raise AccountNotEligible("account is not active")
    if not password_service.verify_password(account["password_hash"], current_password):
        raise PasswordVerificationFailed("current password is incorrect")
    if password_service.verify_password(account["password_hash"], new_password):
        raise InvalidPassword("new password must differ from the current password")

    new_hash = password_service.hash_password(new_password)
    savepoint = "iam_change_password"
    connection.execute(f"SAVEPOINT {savepoint}")
    try:
        updated = connection.execute(
            """UPDATE iam_credentials
               SET password_hash = ?, password_changed_at = ?, must_change_password = 0
               WHERE user_id = ? AND password_hash = ?
                 AND EXISTS (SELECT 1 FROM iam_users WHERE id = ? AND status = 'active')""",
            (new_hash, current_at, user_id, account["password_hash"], user_id),
        )
        if updated.rowcount != 1:
            raise PasswordVerificationFailed(
                "password could not be changed; re-authentication is required"
            )
        connection.execute(
            "UPDATE iam_users SET updated_at = ? WHERE id = ?", (current_at, user_id)
        )
        connection.execute(
            """UPDATE iam_sessions SET revoked_at = ?
               WHERE user_id = ? AND revoked_at IS NULL""",
            (current_at, user_id),
        )
        record_security_event(
            connection, event_type="password_changed", user_id=user_id,
            occurred_at=current_at, success=True,
        )
        connection.execute(f"RELEASE SAVEPOINT {savepoint}")
    except Exception:
        connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
        connection.execute(f"RELEASE SAVEPOINT {savepoint}")
        raise


def change_account_status(
    connection: sqlite3.Connection, *, user_id: str, status: str,
    now: datetime | None = None,
) -> dict[str, str | None]:
    """Disable or lock an account; activation is deliberately not exposed here."""
    if status not in {"disabled", "locked"}:
        raise ValueError("status must be disabled or locked")
    current_at = _iso(_timestamp(now))
    if repository.get_account_by_id(connection, user_id) is None:
        raise AccountNotFound("account does not exist")

    savepoint = "iam_change_account_status"
    connection.execute(f"SAVEPOINT {savepoint}")
    try:
        repository.set_account_status(
            connection, user_id=user_id, status=status, updated_at=current_at,
        )
        revoked = connection.execute(
            """UPDATE iam_sessions SET revoked_at = ?
               WHERE user_id = ? AND revoked_at IS NULL""",
            (current_at, user_id),
        ).rowcount
        record_security_event(
            connection, event_type="account_status_changed", user_id=user_id,
            occurred_at=current_at, success=True,
            metadata={"status": status, "sessions_revoked": revoked},
        )
        connection.execute(f"RELEASE SAVEPOINT {savepoint}")
    except Exception:
        connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
        connection.execute(f"RELEASE SAVEPOINT {savepoint}")
        raise

    row = repository.get_account_by_id(connection, user_id)
    if row is None:
        raise AccountNotFound("account does not exist")
    return _public_account(row)
