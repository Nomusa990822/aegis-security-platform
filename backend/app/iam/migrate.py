"""Explicit, guarded command for applying IAM schema migrations.

Application startup never applies IAM migrations. Operators must deliberately
run python -m app.iam.migrate --apply after taking a verified database backup
and checking the response-audit checkpoint inventory.
"""

import argparse
from datetime import datetime, timezone
import sqlite3

from app.database import get_connection
from app.iam.migrations import apply_migrations


def _assert_database_integrity(connection: sqlite3.Connection) -> None:
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    if integrity != "ok":
        raise RuntimeError(f"SQLite integrity_check failed: {integrity}")
    violations = connection.execute("PRAGMA foreign_key_check").fetchall()
    if violations:
        raise RuntimeError(f"SQLite foreign-key violations detected: {len(violations)}")


def run_migrations(connection: sqlite3.Connection, *, applied_at: str) -> list[int]:
    """Apply IAM migrations only after preflight and verify the result atomically."""
    savepoint = "iam_migration_guard"
    connection.execute(f"SAVEPOINT {savepoint}")
    try:
        _assert_database_integrity(connection)
        applied = apply_migrations(connection, applied_at=applied_at)
        _assert_database_integrity(connection)
        connection.execute(f"RELEASE SAVEPOINT {savepoint}")
        return applied
    except Exception:
        connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
        connection.execute(f"RELEASE SAVEPOINT {savepoint}")
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply AEGIS IAM database migrations")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="explicitly apply pending IAM migrations to AEGIS_DATABASE_PATH",
    )
    args = parser.parse_args()
    if not args.apply:
        parser.error("refusing to modify a database without the explicit --apply flag")

    timestamp = datetime.now(timezone.utc).isoformat()
    with get_connection() as connection:
        applied = run_migrations(connection, applied_at=timestamp)
    if applied:
        print("Applied IAM migration versions: " + ", ".join(map(str, applied)))
    else:
        print("IAM database schema is already current; no changes applied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
