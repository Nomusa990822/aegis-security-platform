"""Versioned, additive SQLite migrations for IAM."""

from dataclasses import dataclass
import hashlib
import sqlite3


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    statements: tuple[str, ...]

    @property
    def checksum(self) -> str:
        canonical = "\n-- statement boundary --\n".join(
            statement.strip() for statement in self.statements
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


MIGRATIONS = (
    Migration(
        version=1,
        name="initial_iam_schema",
        statements=(
            """CREATE TABLE iam_users (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                username_normalized TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL CHECK (role IN ('analyst', 'approver')),
                status TEXT NOT NULL DEFAULT 'invited'
                    CHECK (status IN ('invited', 'active', 'disabled', 'locked')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                activated_at TEXT,
                disabled_at TEXT,
                last_login_at TEXT,
                CHECK (length(id) = 36),
                CHECK (length(username_normalized) BETWEEN 3 AND 128)
            )""",
            """CREATE TABLE iam_credentials (
                user_id TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL CHECK (password_hash LIKE '$argon2id$%'),
                password_changed_at TEXT NOT NULL,
                must_change_password INTEGER NOT NULL DEFAULT 1
                    CHECK (must_change_password IN (0, 1)),
                FOREIGN KEY (user_id) REFERENCES iam_users(id) ON DELETE RESTRICT
            )""",
            """CREATE TABLE iam_mfa_factors (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                factor_type TEXT NOT NULL CHECK (factor_type = 'totp'),
                secret_ciphertext BLOB NOT NULL,
                encryption_key_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'active', 'revoked')),
                last_accepted_step INTEGER CHECK (last_accepted_step IS NULL OR last_accepted_step >= 0),
                created_at TEXT NOT NULL,
                confirmed_at TEXT,
                revoked_at TEXT,
                FOREIGN KEY (user_id) REFERENCES iam_users(id) ON DELETE RESTRICT,
                CHECK (length(id) = 36)
            )""",
            """CREATE UNIQUE INDEX idx_iam_one_active_totp_per_user
                ON iam_mfa_factors(user_id)
                WHERE status = 'active' AND factor_type = 'totp'""",
            """CREATE INDEX idx_iam_mfa_factors_user_status
                ON iam_mfa_factors(user_id, status)""",
            """CREATE TABLE iam_recovery_codes (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                code_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                used_at TEXT,
                FOREIGN KEY (user_id) REFERENCES iam_users(id) ON DELETE RESTRICT,
                CHECK (length(id) = 36)
            )""",
            """CREATE INDEX idx_iam_recovery_codes_user_unused
                ON iam_recovery_codes(user_id, used_at)""",
            """CREATE TABLE iam_access_tokens (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                token_prefix TEXT NOT NULL,
                scopes_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(scopes_json)),
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                last_used_at TEXT,
                revoked_at TEXT,
                revocation_reason TEXT,
                FOREIGN KEY (user_id) REFERENCES iam_users(id) ON DELETE RESTRICT,
                CHECK (length(id) = 36),
                CHECK (length(token_prefix) BETWEEN 4 AND 24)
            )""",
            """CREATE INDEX idx_iam_access_tokens_user_active
                ON iam_access_tokens(user_id, revoked_at, expires_at)""",
            """CREATE TABLE iam_sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                session_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                idle_expires_at TEXT NOT NULL,
                absolute_expires_at TEXT NOT NULL,
                revoked_at TEXT,
                mfa_verified_at TEXT,
                FOREIGN KEY (user_id) REFERENCES iam_users(id) ON DELETE RESTRICT,
                CHECK (length(id) = 36),
                CHECK (absolute_expires_at >= created_at),
                CHECK (idle_expires_at <= absolute_expires_at)
            )""",
            """CREATE INDEX idx_iam_sessions_user_active
                ON iam_sessions(user_id, revoked_at, idle_expires_at, absolute_expires_at)""",
            """CREATE TABLE iam_auth_challenges (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                challenge_hash TEXT NOT NULL UNIQUE,
                purpose TEXT NOT NULL CHECK (purpose = 'login_mfa'),
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed_at TEXT,
                failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
                FOREIGN KEY (user_id) REFERENCES iam_users(id) ON DELETE RESTRICT,
                CHECK (length(id) = 36),
                CHECK (expires_at > created_at)
            )""",
            """CREATE INDEX idx_iam_auth_challenges_user_expiry
                ON iam_auth_challenges(user_id, expires_at, consumed_at)""",
            """CREATE TABLE iam_activation_tokens (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed_at TEXT,
                FOREIGN KEY (user_id) REFERENCES iam_users(id) ON DELETE RESTRICT,
                CHECK (length(id) = 36),
                CHECK (expires_at > created_at)
            )""",
            """CREATE INDEX idx_iam_activation_tokens_user_expiry
                ON iam_activation_tokens(user_id, expires_at, consumed_at)""",
            """CREATE TABLE iam_security_events (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                event_type TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                source_ip TEXT,
                success INTEGER NOT NULL CHECK (success IN (0, 1)),
                metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
                FOREIGN KEY (user_id) REFERENCES iam_users(id) ON DELETE RESTRICT,
                CHECK (length(id) = 36)
            )""",
            """CREATE INDEX idx_iam_security_events_user_time
                ON iam_security_events(user_id, occurred_at)""",
        ),
    ),
)


def apply_migrations(connection: sqlite3.Connection, *, applied_at: str) -> list[int]:
    """Apply pending migrations atomically and verify immutable migration history."""
    if not isinstance(applied_at, str) or not applied_at:
        raise ValueError("applied_at must be a non-empty ISO-8601 string")

    savepoint = "iam_migration_batch"
    connection.execute(f"SAVEPOINT {savepoint}")
    applied: list[int] = []
    try:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS iam_schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                checksum TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )"""
        )
        known = {migration.version: migration for migration in MIGRATIONS}
        rows = connection.execute(
            "SELECT version, name, checksum FROM iam_schema_migrations ORDER BY version"
        ).fetchall()
        applied_versions = set()
        for row in rows:
            version, name, checksum = row
            migration = known.get(version)
            if migration is None:
                raise RuntimeError(f"Database contains unsupported IAM migration version {version}")
            if name != migration.name or checksum != migration.checksum:
                raise RuntimeError(f"IAM migration history mismatch at version {version}")
            applied_versions.add(version)

        ordered_versions = sorted(applied_versions)
        if ordered_versions != list(range(1, len(ordered_versions) + 1)):
            raise RuntimeError("IAM migration history contains a version gap")

        highest = max(applied_versions, default=0)
        for migration in MIGRATIONS:
            if migration.version in applied_versions:
                continue
            if migration.version != highest + 1:
                raise RuntimeError("IAM migrations must be applied in version order")
            for statement in migration.statements:
                connection.execute(statement)
            connection.execute(
                """INSERT INTO iam_schema_migrations
                   (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)""",
                (migration.version, migration.name, migration.checksum, applied_at),
            )
            applied.append(migration.version)
            highest = migration.version

        connection.execute(f"RELEASE SAVEPOINT {savepoint}")
        return applied
    except Exception:
        connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
        connection.execute(f"RELEASE SAVEPOINT {savepoint}")
        raise
