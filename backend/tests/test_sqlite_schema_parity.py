"""Compare the staged SQLAlchemy metadata with the real SQLite initializer.

This is a schema-contract test only. It uses a temporary test database and
never opens the configured application or production database.
"""
from __future__ import annotations

import sqlite3

from app import database
from app.db_schema import metadata
from app.iam.migrations import apply_migrations
from app.idempotency import initialize_idempotency_schema


def _initialize_reference_sqlite_schema(path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", path)
    database.initialize_database()
    with database.get_connection() as connection:
        apply_migrations(
            connection,
            applied_at="2026-11-16T12:00:00+00:00",
        )
    initialize_idempotency_schema()


def test_sqlite_runtime_schema_matches_domain_table_and_column_inventory(
    tmp_path, monkeypatch
):
    database_path = tmp_path / "schema-parity.db"
    _initialize_reference_sqlite_schema(database_path, monkeypatch)

    with sqlite3.connect(database_path) as connection:
        actual_tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
        }

        assert actual_tables == set(metadata.tables)

        for table_name, table in metadata.tables.items():
            actual_columns = {
                row[1]
                for row in connection.execute(
                    f'PRAGMA table_info("{table_name}")'
                )
            }
            assert actual_columns == set(table.columns.keys()), table_name


def test_sqlite_runtime_schema_contains_every_declared_domain_index(
    tmp_path, monkeypatch
):
    database_path = tmp_path / "schema-index-parity.db"
    _initialize_reference_sqlite_schema(database_path, monkeypatch)

    with sqlite3.connect(database_path) as connection:
        for table_name, table in metadata.tables.items():
            actual_indexes = {
                row[1]
                for row in connection.execute(
                    f'PRAGMA index_list("{table_name}")'
                )
                if not row[1].startswith("sqlite_autoindex")
            }
            expected_indexes = {index.name for index in table.indexes}
            assert expected_indexes <= actual_indexes, {
                "table": table_name,
                "missing_indexes": sorted(expected_indexes - actual_indexes),
            }


def test_sqlite_runtime_foreign_keys_match_domain_relationships(
    tmp_path, monkeypatch
):
    database_path = tmp_path / "schema-foreign-key-parity.db"
    _initialize_reference_sqlite_schema(database_path, monkeypatch)
    with sqlite3.connect(database_path) as connection:
        for table_name, table in metadata.tables.items():
            actual = {
                (row[3], row[2], row[4], row[6].upper())
                for row in connection.execute(
                    f'PRAGMA foreign_key_list("{table_name}")'
                )
            }
            expected = {
                (
                    element.parent.name,
                    element.column.table.name,
                    element.column.name,
                    (element.ondelete or "NO ACTION").upper(),
                )
                for constraint in table.foreign_key_constraints
                for element in constraint.elements
            }
            assert actual == expected, {
                "table": table_name,
                "actual": sorted(actual),
                "expected": sorted(expected),
            }
