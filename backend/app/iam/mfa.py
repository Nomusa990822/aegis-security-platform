"""TOTP enrollment, encrypted factor storage, recovery codes, and MFA step-up."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import os
import secrets
import sqlite3
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.iam import totp
from app.iam.passwords import DEFAULT_PASSWORD_SERVICE, PasswordService
from app.iam.security_events import record_security_event

ENROLLMENT_TTL_SECONDS = 15 * 60
RECOVERY_CODE_COUNT = 10
RECENT_MFA_SECONDS = 5 * 60
_RECOVERY_CODE_TTL_SECONDS = 0


def _now(value: datetime | None = None) -> datetime:
    current = datetime.now(timezone.utc) if value is None else value
    if not isinstance(current, datetime) or current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("now must be a timezone-aware datetime")
    return current.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="microseconds")


def _encryption_configuration() -> tuple[bytes, str]:
    raw = os.getenv("AEGIS_MFA_ENCRYPTION_KEY", "")
    key_id = os.getenv("AEGIS_MFA_ENCRYPTION_KEY_ID", "")
    if not raw or not key_id or len(key_id) > 64:
        raise RuntimeError("MFA encryption is not configured")
    try:
        encoded = raw.encode("ascii")
        key = base64.b64decode(encoded + b"=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        if base64.urlsafe_b64encode(key).decode("ascii").rstrip("=") != raw:
            raise ValueError("non-canonical MFA key encoding")
    except (UnicodeEncodeError, ValueError) as exc:
        raise RuntimeError("MFA encryption is not configured") from exc
    if len(key) != 32:
        raise RuntimeError("MFA encryption is not configured")
    return key, key_id


def _associated_data(user_id: str, factor_id: str) -> bytes:
    return f"aegis-iam-totp:v1:{user_id}:{factor_id}".encode("ascii")


def _encrypt_secret(secret: str, *, user_id: str, factor_id: str) -> tuple[bytes, str]:
    key, key_id = _encryption_configuration()
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(
        nonce, secret.encode("ascii"),
        _associated_data(user_id, factor_id),
    )
    return nonce + ciphertext, key_id


def _decrypt_secret(
    ciphertext: bytes, *, key_id: str, user_id: str, factor_id: str
) -> str:
    key, configured_key_id = _encryption_configuration()
    if key_id != configured_key_id or not isinstance(ciphertext, bytes) or len(ciphertext) < 29:
        raise RuntimeError("MFA factor cannot be decrypted with the configured key")
    try:
        plaintext = AESGCM(key).decrypt(
            ciphertext[:12], ciphertext[12:],
            _associated_data(user_id, factor_id),
        )
        secret = plaintext.decode("ascii")
        # Validate canonical Base32 before it can be used.
        totp._decode_secret(secret)
        return secret
    except Exception as exc:
        raise RuntimeError("MFA factor cannot be decrypted with the configured key") from exc


def has_active_totp(connection: sqlite3.Connection, *, user_id: str) -> bool:
    return connection.execute(
        """SELECT 1 FROM iam_mfa_factors
           WHERE user_id = ? AND factor_type = 'totp' AND status = 'active'
           LIMIT 1""",
        (user_id,),
    ).fetchone() is not None


def begin_totp_enrollment(
    connection: sqlite3.Connection, *, user_id: str, issuer: str = "AEGIS",
    now: datetime | None = None,
) -> dict[str, str]:
    """Create an encrypted pending factor; it cannot authenticate until confirmed."""
    current = _now(now)
    current_at = _iso(current)
    user = connection.execute(
        "SELECT username, status FROM iam_users WHERE id = ?", (user_id,)
    ).fetchone()
    if user is None or user["status"] != "active":
        raise ValueError("an active account is required for MFA enrollment")
    if has_active_totp(connection, user_id=user_id):
        raise ValueError("an active TOTP factor already exists")
    connection.execute(
        """UPDATE iam_mfa_factors SET status = 'revoked', revoked_at = ?
           WHERE user_id = ? AND status = 'pending' AND created_at <= ?""",
        (current_at, user_id, _iso(current - timedelta(seconds=ENROLLMENT_TTL_SECONDS))),
    )
    factor_id = str(uuid.uuid4())
    secret = totp.generate_secret()
    ciphertext, key_id = _encrypt_secret(secret, user_id=user_id, factor_id=factor_id)
    connection.execute(
        """INSERT INTO iam_mfa_factors
           (id, user_id, factor_type, secret_ciphertext, encryption_key_id,
            status, last_accepted_step, created_at)
           VALUES (?, ?, 'totp', ?, ?, 'pending', NULL, ?)""",
        (factor_id, user_id, ciphertext, key_id, current_at),
    )
    record_security_event(
        connection, event_type="mfa_enrollment_started", user_id=user_id,
        occurred_at=current_at, success=True,
    )
    label = f"{issuer}:{user['username']}"
    import urllib.parse
    uri = (
        "otpauth://totp/" + urllib.parse.quote(label, safe=":")
        + "?" + urllib.parse.urlencode({
            "secret": secret, "issuer": issuer, "algorithm": "SHA1",
            "digits": 6, "period": 30,
        })
    )
    return {"factor_id": factor_id, "secret": secret, "provisioning_uri": uri}


def _new_recovery_codes(
    connection: sqlite3.Connection, *, user_id: str, created_at: str,
    password_service: PasswordService,
) -> list[str]:
    values: list[str] = []
    for _ in range(RECOVERY_CODE_COUNT):
        code_id = str(uuid.uuid4())
        secret = secrets.token_urlsafe(32)
        raw_code = f"{code_id}.{secret}"
        code_hash = password_service.hash_password(secret)
        connection.execute(
            """INSERT INTO iam_recovery_codes
               (id, user_id, code_hash, created_at, used_at)
               VALUES (?, ?, ?, ?, NULL)""",
            (code_id, user_id, code_hash, created_at),
        )
        values.append(raw_code)
    return values


def confirm_totp_enrollment(
    connection: sqlite3.Connection, *, user_id: str, factor_id: str,
    code: str, now: datetime | None = None,
    password_service: PasswordService = DEFAULT_PASSWORD_SERVICE,
) -> list[str]:
    """Activate a pending factor once and issue one-time recovery codes."""
    current = _now(now)
    current_at = _iso(current)
    row = connection.execute(
        """SELECT id, secret_ciphertext, encryption_key_id, created_at
           FROM iam_mfa_factors
           WHERE id = ? AND user_id = ? AND factor_type = 'totp'
             AND status = 'pending'""",
        (factor_id, user_id),
    ).fetchone()
    if row is None or row["created_at"] <= _iso(current - timedelta(seconds=ENROLLMENT_TTL_SECONDS)):
        raise ValueError("MFA enrollment is invalid or expired")
    secret = _decrypt_secret(
        bytes(row["secret_ciphertext"]), key_id=row["encryption_key_id"],
        user_id=user_id, factor_id=factor_id,
    )
    step = totp.matching_step(secret, code, at_time=current.timestamp())
    if step is None:
        record_security_event(
            connection, event_type="mfa_enrollment_failed", user_id=user_id,
            occurred_at=current_at, success=False,
        )
        raise ValueError("MFA verification failed")
    savepoint = "iam_confirm_totp"
    connection.execute(f"SAVEPOINT {savepoint}")
    try:
        updated = connection.execute(
            """UPDATE iam_mfa_factors
               SET status = 'active', confirmed_at = ?, last_accepted_step = ?
               WHERE id = ? AND user_id = ? AND status = 'pending'""",
            (current_at, step, factor_id, user_id),
        )
        if updated.rowcount != 1:
            raise ValueError("MFA enrollment is invalid or expired")
        codes = _new_recovery_codes(
            connection, user_id=user_id, created_at=current_at,
            password_service=password_service,
        )
        record_security_event(
            connection, event_type="mfa_enrollment_confirmed", user_id=user_id,
            occurred_at=current_at, success=True,
        )
        connection.execute(f"RELEASE SAVEPOINT {savepoint}")
        return codes
    except Exception:
        connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
        connection.execute(f"RELEASE SAVEPOINT {savepoint}")
        raise


def verify_totp(
    connection: sqlite3.Connection, *, user_id: str, code: str,
    now: datetime | None = None,
) -> bool:
    """Verify and atomically advance the accepted TOTP step to prevent replay."""
    current = _now(now)
    current_at = _iso(current)
    row = connection.execute(
        """SELECT id, secret_ciphertext, encryption_key_id, last_accepted_step
           FROM iam_mfa_factors
           WHERE user_id = ? AND factor_type = 'totp' AND status = 'active'""",
        (user_id,),
    ).fetchone()
    if row is None:
        return False
    secret = _decrypt_secret(
        bytes(row["secret_ciphertext"]), key_id=row["encryption_key_id"],
        user_id=user_id, factor_id=row["id"],
    )
    step = totp.matching_step(secret, code, at_time=current.timestamp())
    if step is None or (
        row["last_accepted_step"] is not None
        and step <= row["last_accepted_step"]
    ):
        record_security_event(
            connection, event_type="mfa_verification_failed", user_id=user_id,
            occurred_at=current_at, success=False,
        )
        return False
    updated = connection.execute(
        """UPDATE iam_mfa_factors SET last_accepted_step = ?
           WHERE id = ? AND status = 'active'
             AND (last_accepted_step IS NULL OR last_accepted_step < ?)""",
        (step, row["id"], step),
    )
    if updated.rowcount != 1:
        return False
    record_security_event(
        connection, event_type="mfa_verification_succeeded", user_id=user_id,
        occurred_at=current_at, success=True,
    )
    return True


def consume_recovery_code(
    connection: sqlite3.Connection, *, user_id: str, recovery_code: str,
    now: datetime | None = None,
    password_service: PasswordService = DEFAULT_PASSWORD_SERVICE,
) -> bool:
    """Consume a selector-based Argon2id recovery code exactly once."""
    current_at = _iso(_now(now))
    if not isinstance(recovery_code, str) or not 70 <= len(recovery_code) <= 300:
        return False
    try:
        code_id, secret = recovery_code.split(".", 1)
        if str(uuid.UUID(code_id)) != code_id or not 32 <= len(secret) <= 128:
            return False
    except (ValueError, TypeError, AttributeError):
        return False
    row = connection.execute(
        """SELECT code_hash FROM iam_recovery_codes
           WHERE id = ? AND user_id = ? AND used_at IS NULL""",
        (code_id, user_id),
    ).fetchone()
    if row is None or not password_service.verify_password(row["code_hash"], secret):
        return False
    updated = connection.execute(
        """UPDATE iam_recovery_codes SET used_at = ?
           WHERE id = ? AND user_id = ? AND used_at IS NULL""",
        (current_at, code_id, user_id),
    )
    if updated.rowcount != 1:
        return False
    record_security_event(
        connection, event_type="mfa_recovery_code_used", user_id=user_id,
        occurred_at=current_at, success=True,
    )
    return True


def regenerate_recovery_codes(
    connection: sqlite3.Connection, *, user_id: str, now: datetime | None = None,
    password_service: PasswordService = DEFAULT_PASSWORD_SERVICE,
) -> list[str]:
    current_at = _iso(_now(now))
    if not has_active_totp(connection, user_id=user_id):
        raise ValueError("an active TOTP factor is required")
    savepoint = "iam_regenerate_recovery"
    connection.execute(f"SAVEPOINT {savepoint}")
    try:
        connection.execute(
            """UPDATE iam_recovery_codes SET used_at = ?
               WHERE user_id = ? AND used_at IS NULL""",
            (current_at, user_id),
        )
        codes = _new_recovery_codes(
            connection, user_id=user_id, created_at=current_at,
            password_service=password_service,
        )
        record_security_event(
            connection, event_type="mfa_recovery_codes_regenerated",
            user_id=user_id, occurred_at=current_at, success=True,
        )
        connection.execute(f"RELEASE SAVEPOINT {savepoint}")
        return codes
    except Exception:
        connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
        connection.execute(f"RELEASE SAVEPOINT {savepoint}")
        raise


def mark_session_mfa_verified(
    connection: sqlite3.Connection, *, session_token: str,
    now: datetime | None = None,
) -> bool:
    """Set MFA freshness only for a live server-side session."""
    current_at = _iso(_now(now))
    if not isinstance(session_token, str) or not 40 <= len(session_token) <= 128:
        return False
    try:
        digest = hashlib.sha256(session_token.encode("ascii")).hexdigest()
    except UnicodeEncodeError:
        return False
    updated = connection.execute(
        """UPDATE iam_sessions SET mfa_verified_at = ?
           WHERE session_hash = ? AND revoked_at IS NULL
             AND idle_expires_at > ? AND absolute_expires_at > ?
             AND EXISTS (
                 SELECT 1 FROM iam_users
                 WHERE iam_users.id = iam_sessions.user_id
                   AND iam_users.status = 'active'
             )""",
        (current_at, digest, current_at, current_at),
    )
    if updated.rowcount != 1:
        return False
    user = connection.execute(
        "SELECT user_id FROM iam_sessions WHERE session_hash = ?", (digest,)
    ).fetchone()
    record_security_event(
        connection, event_type="mfa_step_up_succeeded", user_id=user["user_id"],
        occurred_at=current_at, success=True,
    )
    return True


def has_recent_mfa(
    verified_at: str | None, *, now: datetime | None = None,
    max_age_seconds: int = RECENT_MFA_SECONDS,
) -> bool:
    if not isinstance(verified_at, str):
        return False
    current = _now(now)
    try:
        verified = datetime.fromisoformat(verified_at)
        if verified.tzinfo is None or verified.utcoffset() is None:
            return False
    except ValueError:
        return False
    age = (current - verified.astimezone(timezone.utc)).total_seconds()
    return 0 <= age <= max_age_seconds



def create_login_challenge(
    connection: sqlite3.Connection, *, user_id: str,
    now: datetime | None = None, ttl_seconds: int = 5 * 60,
) -> str:
    """Create a short-lived, digest-only second-factor login challenge."""
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 60 <= ttl_seconds <= 10 * 60:
        raise ValueError("MFA challenge lifetime must be between one and ten minutes")
    current = _now(now)
    current_at = _iso(current)
    user = connection.execute(
        "SELECT status FROM iam_users WHERE id = ?", (user_id,)
    ).fetchone()
    if user is None or user["status"] != "active" or not has_active_totp(connection, user_id=user_id):
        raise ValueError("an active account with TOTP is required")
    token = secrets.token_urlsafe(32)
    challenge_id = str(uuid.uuid4())
    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    connection.execute(
        """INSERT INTO iam_auth_challenges
           (id, user_id, challenge_hash, purpose, created_at, expires_at,
            consumed_at, failed_attempts)
           VALUES (?, ?, ?, 'login_mfa', ?, ?, NULL, 0)""",
        (challenge_id, user_id, digest, current_at,
         _iso(current + timedelta(seconds=ttl_seconds))),
    )
    record_security_event(
        connection, event_type="mfa_login_challenge_created",
        user_id=user_id, occurred_at=current_at, success=True,
    )
    return token


def verify_login_challenge(
    connection: sqlite3.Connection, *, challenge_token: str,
    code: str, now: datetime | None = None,
    password_service: PasswordService = DEFAULT_PASSWORD_SERVICE,
) -> str | None:
    """Consume a login challenge after one valid TOTP or recovery-code proof."""
    current = _now(now)
    current_at = _iso(current)
    if not isinstance(challenge_token, str) or not 40 <= len(challenge_token) <= 128:
        return None
    try:
        digest = hashlib.sha256(challenge_token.encode("ascii")).hexdigest()
    except UnicodeEncodeError:
        return None
    row = connection.execute(
        """SELECT id, user_id, expires_at, consumed_at, failed_attempts
           FROM iam_auth_challenges
           WHERE challenge_hash = ? AND purpose = 'login_mfa'""",
        (digest,),
    ).fetchone()
    if (
        row is None or row["consumed_at"] is not None
        or row["expires_at"] <= current_at or row["failed_attempts"] >= 5
    ):
        return None

    valid = verify_totp(connection, user_id=row["user_id"], code=code, now=current)
    if not valid:
        valid = consume_recovery_code(
            connection, user_id=row["user_id"], recovery_code=code,
            now=current, password_service=password_service,
        )
    if not valid:
        connection.execute(
            """UPDATE iam_auth_challenges
               SET failed_attempts = failed_attempts + 1
               WHERE id = ? AND consumed_at IS NULL AND failed_attempts < 5""",
            (row["id"],),
        )
        record_security_event(
            connection, event_type="mfa_login_challenge_failed",
            user_id=row["user_id"], occurred_at=current_at, success=False,
        )
        return None

    consumed = connection.execute(
        """UPDATE iam_auth_challenges SET consumed_at = ?
           WHERE id = ? AND consumed_at IS NULL AND expires_at > ?
             AND failed_attempts < 5""",
        (current_at, row["id"], current_at),
    )
    if consumed.rowcount != 1:
        return None
    record_security_event(
        connection, event_type="mfa_login_challenge_succeeded",
        user_id=row["user_id"], occurred_at=current_at, success=True,
    )
    return row["user_id"]


def issue_mfa_verified_session(
    connection: sqlite3.Connection, *, user_id: str,
    now: datetime | None = None,
):
    """Issue a new session whose MFA timestamp is set only by this server helper."""
    from app.iam.sessions import issue_session

    current_at = _iso(_now(now))
    savepoint = "iam_issue_mfa_session"
    connection.execute(f"SAVEPOINT {savepoint}")
    try:
        issued = issue_session(connection, user_id=user_id, now=_now(now))
        digest = hashlib.sha256(issued.token.encode("ascii")).hexdigest()
        updated = connection.execute(
            """UPDATE iam_sessions SET mfa_verified_at = ?
               WHERE session_hash = ? AND mfa_verified_at IS NULL
                 AND revoked_at IS NULL""",
            (current_at, digest),
        )
        if updated.rowcount != 1:
            raise RuntimeError("MFA-verified session could not be established")
        connection.execute(f"RELEASE SAVEPOINT {savepoint}")
        return issued
    except Exception:
        connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
        connection.execute(f"RELEASE SAVEPOINT {savepoint}")
        raise


def reset_user_mfa(
    connection: sqlite3.Connection, *, user_id: str,
    now: datetime | None = None,
) -> dict[str, int]:
    """Audited local-operator recovery: revoke factors, codes, and all sessions."""
    from app.iam.sessions import revoke_all_user_sessions

    current_at = _iso(_now(now))
    user = connection.execute(
        "SELECT id FROM iam_users WHERE id = ?", (user_id,)
    ).fetchone()
    if user is None:
        raise ValueError("IAM account does not exist")
    factors = connection.execute(
        """UPDATE iam_mfa_factors
           SET status = 'revoked', revoked_at = ?
           WHERE user_id = ? AND status IN ('pending', 'active')""",
        (current_at, user_id),
    ).rowcount
    recovery_codes = connection.execute(
        """UPDATE iam_recovery_codes SET used_at = ?
           WHERE user_id = ? AND used_at IS NULL""",
        (current_at, user_id),
    ).rowcount
    sessions = revoke_all_user_sessions(
        connection, user_id=user_id, now=_now(now)
    )
    record_security_event(
        connection, event_type="mfa_operator_reset", user_id=user_id,
        occurred_at=current_at, success=True,
        metadata={
            "factors_revoked": factors,
            "codes_invalidated": recovery_codes,
            "sessions_revoked": sessions,
        },
    )
    return {
        "factors_revoked": factors,
        "recovery_codes_invalidated": recovery_codes,
        "sessions_revoked": sessions,
    }
