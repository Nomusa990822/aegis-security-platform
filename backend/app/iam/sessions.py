"""Server-managed IAM sessions.

Session bearer values are generated once and returned only to the caller.
Only SHA-256 digests of 256-bit random values are persisted. The digest is
appropriate here because the token is uniformly random and high entropy.
This module is a service layer; it deliberately adds no public login route.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
import sqlite3
import uuid

from app.iam.security_events import record_security_event

DEFAULT_IDLE_TTL_SECONDS = 30 * 60
DEFAULT_ABSOLUTE_TTL_SECONDS = 8 * 60 * 60
MIN_SESSION_TTL_SECONDS = 60
MAX_SESSION_TTL_SECONDS = 24 * 60 * 60


@dataclass(frozen=True)
class IssuedSession:
    session_id: str
    token: str
    created_at: str
    idle_expires_at: str
    absolute_expires_at: str
    mfa_verified_at: None = None


@dataclass(frozen=True)
class ValidatedSession:
    session_id: str
    user_id: str
    role: str
    username: str
    created_at: str
    last_seen_at: str
    idle_expires_at: str
    absolute_expires_at: str
    mfa_verified_at: str | None


def _now(value: datetime | None) -> datetime:
    result = datetime.now(timezone.utc) if value is None else value
    if not isinstance(result, datetime) or result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("now must be a timezone-aware datetime")
    return result.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="microseconds")


def _ttl(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if not MIN_SESSION_TTL_SECONDS <= value <= MAX_SESSION_TTL_SECONDS:
        raise ValueError(f"{name} must be between 60 seconds and 24 hours")
    return value


def _token_hash(token: str) -> str:
    if not isinstance(token, str) or not 40 <= len(token) <= 128:
        raise ValueError("session token is invalid")
    return hashlib.sha256(token.encode("ascii", errors="strict")).hexdigest()


def issue_session(
    connection: sqlite3.Connection,
    *,
    user_id: str,
    now: datetime | None = None,
    idle_ttl_seconds: int = DEFAULT_IDLE_TTL_SECONDS,
    absolute_ttl_seconds: int = DEFAULT_ABSOLUTE_TTL_SECONDS,
) -> IssuedSession:
    """Issue a new password-authenticated session; it is never MFA-verified."""
    idle_ttl = _ttl(idle_ttl_seconds, "idle_ttl_seconds")
    absolute_ttl = _ttl(absolute_ttl_seconds, "absolute_ttl_seconds")
    if idle_ttl > absolute_ttl:
        raise ValueError("idle lifetime cannot exceed absolute lifetime")
    current = _now(now)
    created_at = _iso(current)
    absolute_expires_at = _iso(current + timedelta(seconds=absolute_ttl))
    idle_expires_at = _iso(min(
        current + timedelta(seconds=idle_ttl),
        current + timedelta(seconds=absolute_ttl),
    ))
    user = connection.execute(
        "SELECT id, username, role, status FROM iam_users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if user is None or user["status"] != "active":
        raise ValueError("only active IAM accounts may receive sessions")

    token = secrets.token_urlsafe(32)
    digest = _token_hash(token)
    session_id = str(uuid.uuid4())
    savepoint = "iam_issue_session"
    connection.execute(f"SAVEPOINT {savepoint}")
    try:
        connection.execute(
            """INSERT INTO iam_sessions
               (id, user_id, session_hash, created_at, last_seen_at,
                idle_expires_at, absolute_expires_at, mfa_verified_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, NULL)""",
            (session_id, user_id, digest, created_at, created_at,
             idle_expires_at, absolute_expires_at),
        )
        record_security_event(
            connection, event_type="session_issued", user_id=user_id,
            occurred_at=created_at, success=True,
            metadata={"session_id": session_id, "mfa_verified": False},
        )
        connection.execute(f"RELEASE SAVEPOINT {savepoint}")
    except Exception:
        connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
        connection.execute(f"RELEASE SAVEPOINT {savepoint}")
        raise
    return IssuedSession(
        session_id, token, created_at, idle_expires_at, absolute_expires_at
    )


def validate_session(
    connection: sqlite3.Connection,
    *,
    token: str,
    now: datetime | None = None,
    idle_ttl_seconds: int = DEFAULT_IDLE_TTL_SECONDS,
) -> ValidatedSession | None:
    """Validate and touch a session; expired/revoked/disabled sessions fail closed."""
    idle_ttl = _ttl(idle_ttl_seconds, "idle_ttl_seconds")
    try:
        digest = _token_hash(token)
    except (ValueError, UnicodeError):
        return None
    current = _now(now)
    current_at = _iso(current)
    row = connection.execute(
        """SELECT s.id AS session_id, s.user_id, s.created_at, s.last_seen_at,
                  s.idle_expires_at, s.absolute_expires_at, s.revoked_at,
                  s.mfa_verified_at, u.username, u.role, u.status
           FROM iam_sessions AS s
           JOIN iam_users AS u ON u.id = s.user_id
           WHERE s.session_hash = ?""",
        (digest,),
    ).fetchone()
    if (
        row is None or row["revoked_at"] is not None
        or row["status"] != "active"
        or row["idle_expires_at"] <= current_at
        or row["absolute_expires_at"] <= current_at
    ):
        return None

    next_idle = _iso(min(
        current + timedelta(seconds=idle_ttl),
        datetime.fromisoformat(row["absolute_expires_at"]),
    ))
    updated = connection.execute(
        """UPDATE iam_sessions
           SET last_seen_at = ?, idle_expires_at = ?
           WHERE id = ? AND revoked_at IS NULL
             AND idle_expires_at > ? AND absolute_expires_at > ?
             AND EXISTS (
                 SELECT 1 FROM iam_users
                 WHERE iam_users.id = iam_sessions.user_id
                   AND iam_users.status = 'active'
             )""",
        (current_at, next_idle, row["session_id"], current_at, current_at),
    )
    if updated.rowcount != 1:
        return None
    return ValidatedSession(
        session_id=row["session_id"], user_id=row["user_id"],
        role=row["role"], username=row["username"],
        created_at=row["created_at"], last_seen_at=current_at,
        idle_expires_at=next_idle,
        absolute_expires_at=row["absolute_expires_at"],
        mfa_verified_at=row["mfa_verified_at"],
    )


def revoke_session(
    connection: sqlite3.Connection, *, token: str, now: datetime | None = None
) -> bool:
    """Revoke the presented session idempotently."""
    try:
        digest = _token_hash(token)
    except (ValueError, UnicodeError):
        return False
    current_at = _iso(_now(now))
    row = connection.execute(
        "SELECT id, user_id FROM iam_sessions WHERE session_hash = ?", (digest,)
    ).fetchone()
    if row is None:
        return False
    updated = connection.execute(
        """UPDATE iam_sessions SET revoked_at = ?
           WHERE id = ? AND revoked_at IS NULL""",
        (current_at, row["id"]),
    )
    if updated.rowcount:
        record_security_event(
            connection, event_type="session_revoked", user_id=row["user_id"],
            occurred_at=current_at, success=True,
            metadata={"session_id": row["id"]},
        )
        return True
    return False


def revoke_all_user_sessions(
    connection: sqlite3.Connection, *, user_id: str, now: datetime | None = None
) -> int:
    """Revoke all active sessions for a user and return the affected count."""
    current_at = _iso(_now(now))
    cursor = connection.execute(
        """UPDATE iam_sessions SET revoked_at = ?
           WHERE user_id = ? AND revoked_at IS NULL""",
        (current_at, user_id),
    )
    return cursor.rowcount


def purge_expired_sessions(
    connection: sqlite3.Connection, *, now: datetime | None = None,
    retention_seconds: int = 30 * 24 * 60 * 60,
) -> int:
    """Delete expired/revoked session rows after a retention period."""
    if isinstance(retention_seconds, bool) or not isinstance(retention_seconds, int) or retention_seconds < 0:
        raise ValueError("retention_seconds must be a non-negative integer")
    cutoff = _iso(_now(now) - timedelta(seconds=retention_seconds))
    cursor = connection.execute(
        """DELETE FROM iam_sessions
           WHERE (absolute_expires_at <= ? OR revoked_at <= ?)
             AND created_at <= ?""",
        (cutoff, cutoff, cutoff),
    )
    return cursor.rowcount
