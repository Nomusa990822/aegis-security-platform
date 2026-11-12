"""Transaction-neutral repository for local IAM accounts.

Password hashing and account activation are service responsibilities. The
repository accepts an encoded Argon2id hash only; plaintext passwords are
never accepted or persisted here.
"""

import re
import sqlite3
import unicodedata
import uuid

_USERNAME_RE = re.compile(r"^[\w][\w.@+-]{2,127}$", re.UNICODE)
_VALID_ROLES = {"analyst", "approver"}
_VALID_STATUSES = {"invited", "active", "disabled", "locked"}


def normalize_username(username: str) -> str:
    if not isinstance(username, str):
        raise ValueError("username must be text")
    normalized = unicodedata.normalize("NFKC", username).strip().casefold()
    if not _USERNAME_RE.fullmatch(normalized):
        raise ValueError("username must be 3-128 valid characters")
    return normalized


def create_account(
    connection: sqlite3.Connection,
    *,
    user_id: str,
    username: str,
    role: str,
    password_hash: str,
    created_at: str,
) -> None:
    """Create an invited account using a precomputed Argon2id hash."""
    try:
        parsed_id = uuid.UUID(user_id)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("user_id must be a UUID string") from exc
    if str(parsed_id) != user_id:
        raise ValueError("user_id must use canonical UUID formatting")
    if role not in _VALID_ROLES:
        raise ValueError("role must be analyst or approver")
    if not isinstance(password_hash, str) or not password_hash.startswith("$argon2id$"):
        raise ValueError("password_hash must be an Argon2id encoded hash")
    if not isinstance(created_at, str) or not created_at:
        raise ValueError("created_at is required")

    normalized = normalize_username(username)
    connection.execute(
        """INSERT INTO iam_users
           (id, username, username_normalized, role, status, created_at, updated_at)
           VALUES (?, ?, ?, ?, 'invited', ?, ?)""",
        (user_id, username.strip(), normalized, role, created_at, created_at),
    )
    connection.execute(
        """INSERT INTO iam_credentials
           (user_id, password_hash, password_changed_at, must_change_password)
           VALUES (?, ?, ?, 1)""",
        (user_id, password_hash, created_at),
    )


def get_account_by_username(
    connection: sqlite3.Connection, username: str
) -> sqlite3.Row | None:
    normalized = normalize_username(username)
    return connection.execute(
        """SELECT u.id, u.username, u.username_normalized, u.role, u.status,
                  u.created_at, u.updated_at, u.activated_at, u.disabled_at,
                  u.last_login_at, c.password_hash, c.password_changed_at,
                  c.must_change_password
           FROM iam_users AS u JOIN iam_credentials AS c ON c.user_id = u.id
           WHERE u.username_normalized = ?""",
        (normalized,),
    ).fetchone()


def get_account_by_id(
    connection: sqlite3.Connection, user_id: str
) -> sqlite3.Row | None:
    return connection.execute(
        """SELECT u.id, u.username, u.username_normalized, u.role, u.status,
                  u.created_at, u.updated_at, u.activated_at, u.disabled_at,
                  u.last_login_at, c.password_hash, c.password_changed_at,
                  c.must_change_password
           FROM iam_users AS u JOIN iam_credentials AS c ON c.user_id = u.id
           WHERE u.id = ?""",
        (user_id,),
    ).fetchone()


def set_account_status(
    connection: sqlite3.Connection,
    *,
    user_id: str,
    status: str,
    updated_at: str,
) -> None:
    if status not in _VALID_STATUSES:
        raise ValueError("unsupported account status")
    if not isinstance(updated_at, str) or not updated_at:
        raise ValueError("updated_at is required")
    disabled_at = updated_at if status == "disabled" else None
    cursor = connection.execute(
        """UPDATE iam_users SET status = ?, updated_at = ?, disabled_at = ?
           WHERE id = ?""",
        (status, updated_at, disabled_at, user_id),
    )
    if cursor.rowcount != 1:
        raise LookupError("account does not exist")
