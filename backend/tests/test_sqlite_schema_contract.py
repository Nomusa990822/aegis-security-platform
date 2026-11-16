"""Deep SQLite-to-SQLAlchemy schema contract audit.

Uses only the temporary reference schema created by the application initializers.
No configured database, deployed volume, or production records are opened.
"""
from __future__ import annotations

import re
import sqlite3

from sqlalchemy import Float, Integer, LargeBinary, Text

from app import database
from app.db_schema import metadata
from app.iam.migrations import apply_migrations
from app.idempotency import initialize_idempotency_schema


def _reference_database(path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", path)
    database.initialize_database()
    with database.get_connection() as connection:
        apply_migrations(connection, applied_at="2026-11-16T12:00:00+00:00")
    initialize_idempotency_schema()
    return path


def _affinity(declared_type: str) -> str:
    value = declared_type.upper()
    if "INT" in value:
        return "INTEGER"
    if any(token in value for token in ("CHAR", "CLOB", "TEXT")):
        return "TEXT"
    if "BLOB" in value or not value:
        return "BLOB"
    if any(token in value for token in ("REAL", "FLOA", "DOUB")):
        return "REAL"
    return "NUMERIC"


def _expected_affinity(column):
    if isinstance(column.type, Integer):
        return "INTEGER"
    if isinstance(column.type, LargeBinary):
        return "BLOB"
    if isinstance(column.type, Text):
        return "TEXT"
    if isinstance(column.type, Float):
        return "REAL"
    raise AssertionError(
        f"unreviewed SQLAlchemy type {column.type!r} on "
        f"{column.table.name}.{column.name}"
    )


def _normalise_default(value):
    if value is None:
        return None
    value = str(value).strip()
    if value.upper() == "NULL":
        return None
    while len(value) >= 2 and value[0] == "(" and value[-1] == ")":
        value = value[1:-1].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    return value.lower()


def test_sqlite_column_types_nullability_defaults_and_primary_keys_match_metadata(
    tmp_path, monkeypatch
):
    path = _reference_database(tmp_path / "deep-column-contract.db", monkeypatch)
    failures = []
    with sqlite3.connect(path) as connection:
        for table_name, table in metadata.tables.items():
            actual = {
                row[1]: row
                for row in connection.execute(f'PRAGMA table_info("{table_name}")')
            }
            for column in table.columns:
                row = actual[column.name]
                actual_affinity = _affinity(row[2])
                expected_affinity = _expected_affinity(column)
                if actual_affinity != expected_affinity:
                    failures.append(
                        f"{table_name}.{column.name}: affinity "
                        f"{actual_affinity} != {expected_affinity}"
                    )
                actual_pk = row[5] > 0
                if actual_pk != column.primary_key:
                    failures.append(f"{table_name}.{column.name}: primary-key mismatch")
                if not column.primary_key and bool(row[3]) == bool(column.nullable):
                    failures.append(
                        f"{table_name}.{column.name}: nullable metadata "
                        f"{column.nullable} disagrees with SQLite notnull={row[3]}"
                    )
                actual_default = _normalise_default(row[4])
                expected_default = _normalise_default(
                    getattr(column.server_default, "arg", None)
                    if column.server_default is not None else None
                )
                if actual_default != expected_default:
                    failures.append(
                        f"{table_name}.{column.name}: default "
                        f"{actual_default!r} != {expected_default!r}"
                    )
    assert not failures, "\n".join(failures)


def test_sqlite_index_columns_uniqueness_and_partial_predicates_match_metadata(
    tmp_path, monkeypatch
):
    path = _reference_database(tmp_path / "deep-index-contract.db", monkeypatch)
    failures = []
    with sqlite3.connect(path) as connection:
        for table_name, table in metadata.tables.items():
            actual_indexes = {}
            for row in connection.execute(f'PRAGMA index_list("{table_name}")'):
                index_name, unique, _origin, partial = row[1], bool(row[2]), row[3], bool(row[4])
                columns = tuple(
                    item[2]
                    for item in connection.execute(
                        f'PRAGMA index_info("{index_name}")'
                    )
                )
                sql_row = connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='index' AND name=?",
                    (index_name,),
                ).fetchone()
                sql = sql_row[0] if sql_row else ""
                predicate = None
                if partial:
                    match = re.search(r"\bWHERE\b(.*)$", sql, re.IGNORECASE | re.DOTALL)
                    predicate = re.sub(r"\s+", " ", match.group(1)).strip().lower() if match else ""
                actual_indexes[index_name] = (columns, unique, predicate)

            expected = {}
            for index in table.indexes:
                where = index.dialect_options["sqlite"].get("where")
                predicate = (
                    re.sub(r"\\s+", " ", str(where)).strip().lower()
                    if where is not None else None
                )
                expected[index.name] = (
                    tuple(column.name for column in index.columns),
                    bool(index.unique),
                    predicate,
                )
            for constraint in table.constraints:
                if constraint.__class__.__name__ == "UniqueConstraint":
                    expected[constraint.name or f"unique:{','.join(c.name for c in constraint.columns)}"] = (
                        tuple(column.name for column in constraint.columns),
                        True,
                        None,
                    )

            actual_contracts = set(actual_indexes.values())
            for name, contract in expected.items():
                if contract not in actual_contracts:
                    failures.append(
                        f"{table_name}.{name}: expected index contract {contract!r}; "
                        f"actual={actual_indexes!r}"
                    )
    assert not failures, "\n".join(failures)
