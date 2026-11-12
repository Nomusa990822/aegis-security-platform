"""Explicit, guarded commands for inspecting and applying IAM migrations.

IAM migrations are never applied during application startup. Applying them
requires an existing database plus explicit operator attestations that the
application is stopped, a verified backup exists, and the audit-checkpoint
inventory has been checked.
"""

import argparse
from datetime import datetime, timezone
from pathlib import Path
import sqlite3

from app.database import DATABASE_PATH
from app.iam.migrations import MIGRATIONS, apply_migrations


def _assert_database_integrity(connection: sqlite3.Connection) -> None:
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    if integrity != "ok":
        raise RuntimeError(f"SQLite integrity_check failed: {integrity}")
    violations = connection.execute("PRAGMA foreign_key_check").fetchall()
    if violations:
        raise RuntimeError(
            f"SQLite foreign-key violations detected: {len(violations)}"
        )


def _validate_migration_history(connection: sqlite3.Connection) -> list[int]:
    """Validate the recorded history and return unapplied migration versions."""
    exists = connection.execute(
        """SELECT 1 FROM sqlite_master
           WHERE type = 'table' AND name = 'iam_schema_migrations'"""
    ).fetchone()
    if exists is None:
        return [migration.version for migration in MIGRATIONS]

    known = {migration.version: migration for migration in MIGRATIONS}
    rows = connection.execute(
        """SELECT version, name, checksum
           FROM iam_schema_migrations ORDER BY version"""
    ).fetchall()
    recorded = []
    for row in rows:
        version, name, checksum = row
        migration = known.get(version)
        if migration is None:
            raise RuntimeError(
                f"Database contains unsupported IAM migration version {version}"
            )
        if name != migration.name or checksum != migration.checksum:
            raise RuntimeError(
                f"IAM migration history mismatch at version {version}"
            )
        recorded.append(version)

    if recorded != list(range(1, len(recorded) + 1)):
        raise RuntimeError("IAM migration history contains a version gap")

    applied = set(recorded)
    return [
        migration.version
        for migration in MIGRATIONS
        if migration.version not in applied
    ]


def run_migrations(
    connection: sqlite3.Connection, *, applied_at: str
) -> list[int]:
    """Apply pending migrations atomically, with integrity checks before/after."""
    savepoint = "iam_migration_guard"
    connection.execute(f"SAVEPOINT {savepoint}")
    try:
        _assert_database_integrity(connection)
        _validate_migration_history(connection)
        applied = apply_migrations(connection, applied_at=applied_at)
        _assert_database_integrity(connection)
        connection.execute(f"RELEASE SAVEPOINT {savepoint}")
        return applied
    except Exception:
        connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
        connection.execute(f"RELEASE SAVEPOINT {savepoint}")
        raise


def _open_existing_database(path: Path, *, read_only: bool) -> sqlite3.Connection:
    """Open only an existing regular database; never create a file implicitly."""
    if path.is_symlink():
        raise RuntimeError("Refusing to migrate a database path that is a symlink.")
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"Database does not exist: {path}. Refusing to create a new database."
        ) from exc
    if not resolved.is_file():
        raise RuntimeError(f"Database path is not a regular file: {resolved}")

    mode = "ro" if read_only else "rw"
    connection = sqlite3.connect(
        f"{resolved.as_uri()}?mode={mode}",
        uri=True,
        timeout=30,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")
    if read_only:
        connection.execute("PRAGMA query_only = ON")
    return connection


def _check_database(path: Path) -> list[int]:
    connection = _open_existing_database(path, read_only=True)
    try:
        _assert_database_integrity(connection)
        return _validate_migration_history(connection)
    finally:
        connection.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Inspect or explicitly apply AEGIS IAM database migrations"
    )
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument(
        "--check",
        action="store_true",
        help="read-only integrity and migration-history preflight",
    )
    action.add_argument(
        "--apply",
        action="store_true",
        help="apply pending migrations to the existing AEGIS database",
    )
    parser.add_argument(
        "--backup-verified",
        action="store_true",
        help="attest that a restorable database backup has been verified",
    )
    parser.add_argument(
        "--audit-inventory-verified",
        action="store_true",
        help="attest that the signed audit-checkpoint inventory was verified",
    )
    parser.add_argument(
        "--application-stopped",
        action="store_true",
        help="attest that the AEGIS application/container is stopped",
    )
    args = parser.parse_args(argv)

    if args.apply and not (
        args.backup_verified
        and args.audit_inventory_verified
        and args.application_stopped
    ):
        parser.error(
            "--apply requires --backup-verified, "
            "--audit-inventory-verified, and --application-stopped"
        )
    if args.check and (
        args.backup_verified
        or args.audit_inventory_verified
        or args.application_stopped
    ):
        parser.error("operator attestation flags are only valid with --apply")

    if args.check:
        pending = _check_database(DATABASE_PATH)
        if pending:
            print("Pending IAM migration versions: " + ", ".join(map(str, pending)))
        else:
            print("IAM schema is current; no pending migrations.")
        print("Read-only preflight passed; no database changes were made.")
        return 0

    timestamp = datetime.now(timezone.utc).isoformat()
    connection = _open_existing_database(DATABASE_PATH, read_only=False)
    try:
        applied = run_migrations(connection, applied_at=timestamp)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()

    if applied:
        print("Applied IAM migration versions: " + ", ".join(map(str, applied)))
    else:
        print("IAM database schema is already current; no changes applied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
