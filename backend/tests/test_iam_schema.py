import sqlite3

import pytest

from app.iam.migrations import MIGRATIONS, apply_migrations
from app.iam.repository import (
    create_account,
    get_account_by_id,
    get_account_by_username,
    normalize_username,
    set_account_status,
)

NOW = "2026-11-12T10:00:00+00:00"
ARGON_HASH = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnZXN0"
USER_ID = "12345678-1234-4234-8234-123456789012"


@pytest.fixture
def connection():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    try:
        apply_migrations(db, applied_at=NOW)
        yield db
    finally:
        db.close()


def test_initial_migration_creates_iam_tables(connection):
    tables = {row[0] for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
    )}
    assert {
        "iam_schema_migrations", "iam_users", "iam_credentials",
        "iam_mfa_factors", "iam_recovery_codes", "iam_access_tokens",
        "iam_sessions", "iam_auth_challenges", "iam_activation_tokens",
        "iam_security_events",
    } <= tables
    assert tuple(connection.execute(
        "SELECT version, name FROM iam_schema_migrations"
    ).fetchone()) == (1, "initial_iam_schema")


def test_migration_is_idempotent(connection):
    assert apply_migrations(connection, applied_at=NOW) == []
    assert connection.execute("SELECT COUNT(*) FROM iam_schema_migrations").fetchone()[0] == 1


def test_migration_checksum_detects_modified_history(connection):
    connection.execute(
        "UPDATE iam_schema_migrations SET checksum = ? WHERE version = 1",
        ("0" * 64,),
    )
    with pytest.raises(RuntimeError, match="history mismatch"):
        apply_migrations(connection, applied_at=NOW)


def test_migration_rejects_unknown_future_version(connection):
    connection.execute(
        "INSERT INTO iam_schema_migrations VALUES (?, ?, ?, ?)",
        (99, "future", "f" * 64, NOW),
    )
    with pytest.raises(RuntimeError, match="unsupported IAM migration version"):
        apply_migrations(connection, applied_at=NOW)


def test_failed_migration_rolls_back_all_schema_changes():
    db = sqlite3.connect(":memory:")
    broken = type(MIGRATIONS[0])(
        1, "broken",
        (
            "CREATE TABLE iam_should_rollback (id INTEGER PRIMARY KEY)",
            "CREATE TABLE iam_should_rollback (id INTEGER PRIMARY KEY)",
        ),
    )
    import app.iam.migrations as migrations
    original = migrations.MIGRATIONS
    migrations.MIGRATIONS = (broken,)
    try:
        with pytest.raises(sqlite3.OperationalError):
            apply_migrations(db, applied_at=NOW)
        assert db.execute(
            "SELECT name FROM sqlite_master WHERE name = 'iam_schema_migrations'"
        ).fetchone() is None
        assert db.execute(
            "SELECT name FROM sqlite_master WHERE name = 'iam_should_rollback'"
        ).fetchone() is None
    finally:
        migrations.MIGRATIONS = original
        db.close()


def test_migration_preserves_existing_response_audit_rows():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE response_audit_log (id INTEGER PRIMARY KEY, actor TEXT, event_hash TEXT)")
    db.execute(
        "INSERT INTO response_audit_log VALUES (?, ?, ?)",
        (1, "legacy-approver", "a" * 64),
    )
    before = db.execute("SELECT id, actor, event_hash FROM response_audit_log").fetchall()
    apply_migrations(db, applied_at=NOW)
    after = db.execute("SELECT id, actor, event_hash FROM response_audit_log").fetchall()
    assert after == before
    db.close()


def test_username_normalization_is_unicode_aware_and_case_insensitive():
    assert normalize_username("  Analyst.One  ") == "analyst.one"
    assert normalize_username("ＡNALYST") == "analyst"
    with pytest.raises(ValueError):
        normalize_username("ab")


def test_account_repository_stores_argon2id_hash_only(connection):
    create_account(
        connection, user_id=USER_ID, username="Analyst.One", role="analyst",
        password_hash=ARGON_HASH, created_at=NOW,
    )
    account = get_account_by_username(connection, " analyst.ONE ")
    assert account["id"] == USER_ID
    assert account["username_normalized"] == "analyst.one"
    assert account["password_hash"] == ARGON_HASH
    assert account["status"] == "invited"


def test_account_repository_rejects_plaintext_password(connection):
    with pytest.raises(ValueError, match="Argon2id"):
        create_account(
            connection, user_id=USER_ID, username="analyst.one", role="analyst",
            password_hash="plaintext-password", created_at=NOW,
        )
    assert connection.execute("SELECT COUNT(*) FROM iam_users").fetchone()[0] == 0


def test_duplicate_normalized_usernames_are_rejected(connection):
    create_account(
        connection, user_id=USER_ID, username="Analyst.One", role="analyst",
        password_hash=ARGON_HASH, created_at=NOW,
    )
    with pytest.raises(sqlite3.IntegrityError):
        create_account(
            connection, user_id="22345678-1234-4234-8234-123456789012",
            username=" analyst.one ", role="approver",
            password_hash=ARGON_HASH, created_at=NOW,
        )


def test_account_lookup_and_status_change(connection):
    create_account(
        connection, user_id=USER_ID, username="analyst.one", role="analyst",
        password_hash=ARGON_HASH, created_at=NOW,
    )
    assert get_account_by_id(connection, USER_ID)["role"] == "analyst"
    set_account_status(connection, user_id=USER_ID, status="disabled", updated_at=NOW)
    account = get_account_by_id(connection, USER_ID)
    assert account["status"] == "disabled"
    assert account["disabled_at"] == NOW
    with pytest.raises(LookupError):
        set_account_status(
            connection, user_id="32345678-1234-4234-8234-123456789012",
            status="disabled", updated_at=NOW,
        )


def test_iam_foreign_keys_prevent_orphaned_credentials(connection):
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            "INSERT INTO iam_credentials VALUES (?, ?, ?, 1)",
            (USER_ID, ARGON_HASH, NOW),
        )


def test_only_one_active_totp_factor_per_user(connection):
    create_account(
        connection, user_id=USER_ID, username="analyst.one", role="analyst",
        password_hash=ARGON_HASH, created_at=NOW,
    )
    statement = """INSERT INTO iam_mfa_factors
        (id, user_id, factor_type, secret_ciphertext, encryption_key_id, status, created_at)
        VALUES (?, ?, 'totp', ?, 'key-v1', 'active', ?)"""
    connection.execute(statement, ("42345678-1234-4234-8234-123456789012", USER_ID, b"cipher", NOW))
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(statement, ("52345678-1234-4234-8234-123456789012", USER_ID, b"cipher2", NOW))


def test_application_startup_does_not_automatically_apply_iam_migrations(isolated_database):
    from fastapi.testclient import TestClient

    from app.main import app
    from app.database import get_connection

    with TestClient(app):
        with get_connection() as db:
            migration_table = db.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name = 'iam_schema_migrations'"
            ).fetchone()
    assert migration_table is None


def test_explicit_migration_runner_applies_schema_after_integrity_preflight():
    from app.iam.migrate import run_migrations

    db = sqlite3.connect(":memory:")
    db.execute("PRAGMA foreign_keys = ON")
    assert run_migrations(db, applied_at=NOW) == [1]
    assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert db.execute("PRAGMA foreign_key_check").fetchall() == []
    db.close()


def test_explicit_migration_runner_refuses_existing_integrity_violations():
    from app.iam.migrate import run_migrations

    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE parent (id INTEGER PRIMARY KEY)")
    db.execute("CREATE TABLE child (parent_id INTEGER REFERENCES parent(id))")
    db.execute("PRAGMA foreign_keys = OFF")
    db.execute("INSERT INTO child VALUES (404)")
    db.execute("PRAGMA foreign_keys = ON")
    with pytest.raises(RuntimeError, match="foreign-key violations"):
        run_migrations(db, applied_at=NOW)
    assert db.execute(
        "SELECT name FROM sqlite_master WHERE name = 'iam_schema_migrations'"
    ).fetchone() is None
    db.close()



def test_migration_history_rejects_missing_earlier_version(monkeypatch):
    import app.iam.migrations as migrations

    first = type(MIGRATIONS[0])(1, "first", ("CREATE TABLE first_table (id INTEGER)",))
    second = type(MIGRATIONS[0])(2, "second", ("CREATE TABLE second_table (id INTEGER)",))
    monkeypatch.setattr(migrations, "MIGRATIONS", (first, second))

    db = sqlite3.connect(":memory:")
    db.execute(
        """CREATE TABLE iam_schema_migrations (
            version INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE,
            checksum TEXT NOT NULL, applied_at TEXT NOT NULL
        )"""
    )
    db.execute(
        "INSERT INTO iam_schema_migrations VALUES (?, ?, ?, ?)",
        (2, second.name, second.checksum, NOW),
    )
    with pytest.raises(RuntimeError, match="version gap"):
        migrations.apply_migrations(db, applied_at=NOW)
    assert db.execute(
        "SELECT name FROM sqlite_master WHERE name = 'first_table'"
    ).fetchone() is None
    db.close()


def test_migration_cli_refuses_to_create_missing_database(monkeypatch, tmp_path):
    import app.iam.migrate as migrate

    missing = tmp_path / "must-not-be-created.db"
    monkeypatch.setattr(migrate, "DATABASE_PATH", missing)
    with pytest.raises(RuntimeError, match="Refusing to create a new database"):
        migrate._check_database(missing)
    assert not missing.exists()


def test_migration_cli_requires_explicit_operator_attestations():
    import app.iam.migrate as migrate

    with pytest.raises(SystemExit) as error:
        migrate.main(["--apply"])
    assert error.value.code == 2


def test_migration_cli_check_is_read_only(monkeypatch, tmp_path, capsys):
    import app.iam.migrate as migrate

    database_path = tmp_path / "existing.db"
    db = sqlite3.connect(database_path)
    db.execute("CREATE TABLE keep_me (id INTEGER PRIMARY KEY)")
    db.commit()
    db.close()
    monkeypatch.setattr(migrate, "DATABASE_PATH", database_path)

    assert migrate.main(["--check"]) == 0
    output = capsys.readouterr().out
    assert "Read-only preflight passed" in output

    db = sqlite3.connect(database_path)
    assert db.execute(
        "SELECT name FROM sqlite_master WHERE name = 'iam_schema_migrations'"
    ).fetchone() is None
    db.close()



def test_account_repository_requires_canonical_lowercase_uuid(connection):
    with pytest.raises(ValueError, match="canonical UUID"):
        create_account(
            connection,
            user_id="12345678-1234-4234-8234-1234567890AB",
            username="analyst.one",
            role="analyst",
            password_hash=ARGON_HASH,
            created_at=NOW,
        )
