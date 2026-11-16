from datetime import datetime, timedelta, timezone
import base64
import sqlite3

import pytest

from app.iam import mfa, totp
from app.iam.accounts import activate_account, create_invitation
from app.iam.migrations import apply_migrations
from app.iam.passwords import PasswordService
from app.iam.sessions import issue_session

NOW = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)
PASSWORDS = PasswordService(memory_cost=1024, time_cost=1, parallelism=1)


@pytest.fixture
def connection(monkeypatch):
    key = base64.urlsafe_b64encode(b"k" * 32).decode("ascii").rstrip("=")
    monkeypatch.setenv("AEGIS_MFA_ENCRYPTION_KEY", key)
    monkeypatch.setenv("AEGIS_MFA_ENCRYPTION_KEY_ID", "test-key-v1")
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    apply_migrations(db, applied_at=NOW.isoformat())
    invitation = create_invitation(
        db, username="mfa.user", role="approver", now=NOW,
        password_service=PASSWORDS,
    )
    activate_account(
        db, activation_token=invitation.activation_token,
        new_password="correct horse battery staple", now=NOW,
        password_service=PASSWORDS,
    )
    db.commit()
    try:
        yield db, invitation.user_id
    finally:
        db.close()


def test_rfc6238_six_digit_vector():
    secret = base64.b32encode(b"12345678901234567890").decode("ascii").rstrip("=")
    assert totp.code_at(secret, at_time=59) == "287082"


def test_totp_rejects_malformed_code_and_secret():
    assert totp.matching_step("JBSWY3DPEHPK3PXP", "12AB56", at_time=1_700_000_000) is None
    assert totp.matching_step("not-a-secret", "123456", at_time=1_700_000_000) is None


def test_enrollment_is_pending_until_confirmed_and_secret_is_encrypted(connection):
    db, user_id = connection
    enrollment = mfa.begin_totp_enrollment(db, user_id=user_id, now=NOW)
    row = db.execute(
        "SELECT secret_ciphertext, status FROM iam_mfa_factors WHERE id = ?",
        (enrollment["factor_id"],),
    ).fetchone()
    assert row["status"] == "pending"
    assert enrollment["secret"].encode("ascii") not in bytes(row["secret_ciphertext"])
    assert not mfa.has_active_totp(db, user_id=user_id)

    codes = mfa.confirm_totp_enrollment(
        db, user_id=user_id, factor_id=enrollment["factor_id"],
        code=totp.code_at(enrollment["secret"], at_time=NOW.timestamp()),
        now=NOW, password_service=PASSWORDS,
    )
    assert len(codes) == mfa.RECOVERY_CODE_COUNT
    assert mfa.has_active_totp(db, user_id=user_id)
    assert all(len(code) >= 70 for code in codes)
    stored = db.execute(
        "SELECT code_hash FROM iam_recovery_codes WHERE user_id = ?", (user_id,)
    ).fetchall()
    assert len(stored) == len(codes)
    assert all(code.split(".", 1)[1] not in row["code_hash"] for code in codes for row in stored)


def test_totp_verification_is_replay_resistant(connection):
    db, user_id = connection
    enrollment = mfa.begin_totp_enrollment(db, user_id=user_id, now=NOW)
    initial_code = totp.code_at(enrollment["secret"], at_time=NOW.timestamp())
    mfa.confirm_totp_enrollment(
        db, user_id=user_id, factor_id=enrollment["factor_id"],
        code=initial_code, now=NOW, password_service=PASSWORDS,
    )
    later = NOW + timedelta(seconds=30)
    later_code = totp.code_at(enrollment["secret"], at_time=later.timestamp())
    assert mfa.verify_totp(db, user_id=user_id, code=later_code, now=later)
    assert not mfa.verify_totp(db, user_id=user_id, code=later_code, now=later)


def test_recovery_codes_are_single_use_and_regeneration_invalidates_old_codes(connection):
    db, user_id = connection
    enrollment = mfa.begin_totp_enrollment(db, user_id=user_id, now=NOW)
    codes = mfa.confirm_totp_enrollment(
        db, user_id=user_id, factor_id=enrollment["factor_id"],
        code=totp.code_at(enrollment["secret"], at_time=NOW.timestamp()),
        now=NOW, password_service=PASSWORDS,
    )
    assert mfa.consume_recovery_code(
        db, user_id=user_id, recovery_code=codes[0], now=NOW,
        password_service=PASSWORDS,
    )
    assert not mfa.consume_recovery_code(
        db, user_id=user_id, recovery_code=codes[0], now=NOW,
        password_service=PASSWORDS,
    )
    replacement = mfa.regenerate_recovery_codes(
        db, user_id=user_id, now=NOW + timedelta(seconds=1),
        password_service=PASSWORDS,
    )
    assert len(replacement) == mfa.RECOVERY_CODE_COUNT
    assert not mfa.consume_recovery_code(
        db, user_id=user_id, recovery_code=codes[1],
        now=NOW + timedelta(seconds=2), password_service=PASSWORDS,
    )
    assert mfa.consume_recovery_code(
        db, user_id=user_id, recovery_code=replacement[0],
        now=NOW + timedelta(seconds=2), password_service=PASSWORDS,
    )


def test_mfa_step_up_is_server_side_and_requires_live_session(connection):
    db, user_id = connection
    issued = issue_session(db, user_id=user_id, now=NOW)
    assert mfa.mark_session_mfa_verified(
        db, session_token=issued.token, now=NOW + timedelta(seconds=1)
    )
    row = db.execute(
        "SELECT mfa_verified_at FROM iam_sessions WHERE id = ?",
        (issued.session_id,),
    ).fetchone()
    assert mfa.has_recent_mfa(row["mfa_verified_at"], now=NOW + timedelta(seconds=60))
    assert not mfa.has_recent_mfa(
        row["mfa_verified_at"], now=NOW + timedelta(seconds=RECENT_WINDOW + 2)
    )


RECENT_WINDOW = mfa.RECENT_MFA_SECONDS


def test_encryption_fails_closed_when_key_is_missing(connection, monkeypatch):
    db, user_id = connection
    monkeypatch.delenv("AEGIS_MFA_ENCRYPTION_KEY")
    with pytest.raises(RuntimeError, match="not configured"):
        mfa.begin_totp_enrollment(db, user_id=user_id, now=NOW)


def test_wrong_key_or_tampered_ciphertext_is_rejected(connection, monkeypatch):
    db, user_id = connection
    enrollment = mfa.begin_totp_enrollment(db, user_id=user_id, now=NOW)
    row = db.execute(
        "SELECT secret_ciphertext, encryption_key_id FROM iam_mfa_factors WHERE id = ?",
        (enrollment["factor_id"],),
    ).fetchone()
    tampered = bytes(row["secret_ciphertext"][:-1]) + bytes([row["secret_ciphertext"][-1] ^ 1])
    with pytest.raises(RuntimeError, match="cannot be decrypted"):
        mfa._decrypt_secret(
            tampered, key_id=row["encryption_key_id"],
            user_id=user_id, factor_id=enrollment["factor_id"],
        )
    monkeypatch.setenv(
        "AEGIS_MFA_ENCRYPTION_KEY",
        base64.urlsafe_b64encode(b"z" * 32).decode("ascii").rstrip("="),
    )
    with pytest.raises(RuntimeError, match="cannot be decrypted"):
        mfa._decrypt_secret(
            bytes(row["secret_ciphertext"]), key_id=row["encryption_key_id"],
            user_id=user_id, factor_id=enrollment["factor_id"],
        )
