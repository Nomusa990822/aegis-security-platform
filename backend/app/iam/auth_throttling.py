"""Persistent, privacy-preserving authentication throttling primitives.

The table stores HMAC fingerprints, never raw usernames or client addresses.
The caller must obtain the client address only from a trusted ASGI connection
or explicitly configured reverse-proxy boundary.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import sqlite3
import re

from app.iam.security_events import record_security_event


@dataclass(frozen=True)
class ThrottleDecision:
    allowed: bool
    failures: int
    blocked_until: str | None
    retry_after_seconds: int


def _timestamp(value: datetime | None) -> datetime:
    current = datetime.now(timezone.utc) if value is None else value
    if not isinstance(current, datetime) or current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("now must be a timezone-aware datetime")
    return current.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="microseconds")


def _fingerprint(scope: str, identifier: str, secret: str | bytes) -> str:
    if not isinstance(scope, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", scope):
        raise ValueError("scope must be a lowercase, non-identifying scope label")
    if not isinstance(identifier, str) or not 1 <= len(identifier) <= 512:
        raise ValueError("identifier must contain 1-512 characters")
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("throttling HMAC secret must contain at least 32 bytes")
    message = b"aegis-auth-throttle-v1:" + scope.encode("utf-8") + b":" + identifier.encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def record_authentication_failure(
    connection: sqlite3.Connection,
    *,
    scope: str,
    identifier: str,
    secret: str | bytes,
    now: datetime | None = None,
    max_failures: int = 5,
    window_seconds: int = 15 * 60,
    lockout_seconds: int = 15 * 60,
) -> ThrottleDecision:
    """Atomically record one failure and calculate whether the bucket is blocked."""
    for name, value in (
        ("max_failures", max_failures),
        ("window_seconds", window_seconds),
        ("lockout_seconds", lockout_seconds),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
    current = _timestamp(now)
    now_at = _iso(current)
    cutoff = _iso(current - timedelta(seconds=window_seconds))
    blocked_until = _iso(current + timedelta(seconds=lockout_seconds))
    bucket = _fingerprint(scope, identifier, secret)
    row = connection.execute(
        """INSERT INTO iam_auth_rate_limits
           (bucket_hash, scope, window_started_at, failures, blocked_until, updated_at)
           VALUES (?, ?, ?, 1, NULL, ?)
           ON CONFLICT(bucket_hash) DO UPDATE SET
             window_started_at = CASE
               WHEN iam_auth_rate_limits.window_started_at <= ?
               THEN excluded.window_started_at
               ELSE iam_auth_rate_limits.window_started_at END,
             failures = CASE
               WHEN iam_auth_rate_limits.window_started_at <= ? THEN 1
               ELSE iam_auth_rate_limits.failures + 1 END,
             blocked_until = CASE
               WHEN iam_auth_rate_limits.blocked_until > ? THEN iam_auth_rate_limits.blocked_until
               WHEN (CASE
                 WHEN iam_auth_rate_limits.window_started_at <= ? THEN 1
                 ELSE iam_auth_rate_limits.failures + 1 END) >= ?
               THEN ?
               ELSE NULL END,
             updated_at = excluded.updated_at
           RETURNING failures, blocked_until""",
        (bucket, scope, now_at, now_at, cutoff, cutoff, now_at,
         cutoff, max_failures, blocked_until),
    ).fetchone()
    is_blocked = row["blocked_until"] is not None and row["blocked_until"] > now_at
    if is_blocked and row["blocked_until"] == blocked_until:
        record_security_event(
            connection, event_type="authentication_throttled",
            occurred_at=now_at, success=False,
            metadata={"scope": scope, "failure_count": row["failures"]},
        )
    retry = 0
    if is_blocked:
        retry = max(1, int((datetime.fromisoformat(row["blocked_until"]) - current).total_seconds() + 0.999))
    return ThrottleDecision(not is_blocked, row["failures"], row["blocked_until"], retry)


def authentication_succeeded(
    connection: sqlite3.Connection,
    *,
    scope: str,
    identifier: str,
    secret: str | bytes,
) -> bool:
    """Clear a single matching fingerprint after successful authentication."""
    bucket = _fingerprint(scope, identifier, secret)
    cursor = connection.execute(
        "DELETE FROM iam_auth_rate_limits WHERE bucket_hash = ?", (bucket,)
    )
    return cursor.rowcount > 0


def is_authentication_blocked(
    connection: sqlite3.Connection,
    *,
    scope: str,
    identifier: str,
    secret: str | bytes,
    now: datetime | None = None,
) -> ThrottleDecision:
    """Read the persistent block state without incrementing the failure counter."""
    current_at = _iso(_timestamp(now))
    bucket = _fingerprint(scope, identifier, secret)
    row = connection.execute(
        """SELECT failures, blocked_until FROM iam_auth_rate_limits
           WHERE bucket_hash = ?""",
        (bucket,),
    ).fetchone()
    if row is None or row["blocked_until"] is None or row["blocked_until"] <= current_at:
        return ThrottleDecision(True, 0 if row is None else row["failures"], None, 0)
    retry = max(1, int((datetime.fromisoformat(row["blocked_until"]) - datetime.fromisoformat(current_at)).total_seconds() + 0.999))
    return ThrottleDecision(False, row["failures"], row["blocked_until"], retry)


def purge_authentication_throttles(
    connection: sqlite3.Connection,
    *,
    now: datetime | None = None,
    retention_seconds: int = 24 * 60 * 60,
) -> int:
    if isinstance(retention_seconds, bool) or not isinstance(retention_seconds, int) or retention_seconds < 0:
        raise ValueError("retention_seconds must be a non-negative integer")
    cutoff = _iso(_timestamp(now) - timedelta(seconds=retention_seconds))
    return connection.execute(
        "DELETE FROM iam_auth_rate_limits WHERE updated_at <= ?", (cutoff,)
    ).rowcount
