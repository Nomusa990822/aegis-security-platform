"""Cross-dialect CHECK, key and PostgreSQL DDL contract tests."""
from __future__ import annotations

import re
import sqlite3

from sqlalchemy import CheckConstraint
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.schema import CreateIndex, CreateTable

from app import database
from app.db_schema import metadata
from app.iam.migrations import apply_migrations
from app.idempotency import initialize_idempotency_schema


def _initialize_reference(path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", path)
    database.initialize_database()
    with database.get_connection() as connection:
        apply_migrations(connection, applied_at="2026-11-16T12:00:00+00:00")
    initialize_idempotency_schema()


def _extract_check_expressions(create_sql: str) -> set[str]:
    expressions = set()
    for match in re.finditer(r"CHECK\s*\(", create_sql, re.IGNORECASE):
        start = match.end()
        depth = 1
        quote = None
        index = start
        while index < len(create_sql) and depth:
            char = create_sql[index]
            if quote:
                if char == quote:
                    if index + 1 < len(create_sql) and create_sql[index + 1] == quote:
                        index += 1
                    else:
                        quote = None
            elif char in ("'", '"', "`"):
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            index += 1
        if depth == 0:
            expressions.add(_normalise_sql(create_sql[start:index - 1]))
    return expressions


def _normalise_sql(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().lower()


def test_sqlite_check_constraints_match_runtime_schema(tmp_path, monkeypatch):
    path = tmp_path / "check-constraint-parity.db"
    _initialize_reference(path, monkeypatch)
    failures = []

    with sqlite3.connect(path) as connection:
        for table_name, table in metadata.tables.items():
            row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                (table_name,),
            ).fetchone()
            actual = _extract_check_expressions(row[0] or "")
            expected = {
                _normalise_sql(
                    str(constraint.sqltext.compile(dialect=sqlite.dialect()))
                )
                for constraint in table.constraints
                if isinstance(constraint, CheckConstraint)
            }
            if actual != expected:
                failures.append(
                    f"{table_name}: missing_from_model={sorted(actual - expected)!r}; "
                    f"not_in_source={sorted(expected - actual)!r}"
                )

    assert not failures, "\n".join(failures)


def test_sqlite_composite_primary_and_unique_keys_match_metadata(tmp_path, monkeypatch):
    path = tmp_path / "key-parity.db"
    _initialize_reference(path, monkeypatch)
    failures = []

    with sqlite3.connect(path) as connection:
        for table_name, table in metadata.tables.items():
            pk_actual = tuple(
                name for _ordinal, name in sorted(
                    (row[5], row[1])
                    for row in connection.execute(f'PRAGMA table_info("{table_name}")')
                    if row[5] > 0
                )
            )
            pk_expected = tuple(
                column.name for column in sorted(
                    (column for column in table.columns if column.primary_key),
                    key=lambda column: list(table.primary_key.columns).index(column),
                )
            )
            if pk_actual != pk_expected:
                failures.append(
                    f"{table_name}: primary key {pk_actual!r} != {pk_expected!r}"
                )

            actual_unique = set()
            for row in connection.execute(f'PRAGMA index_list("{table_name}")'):
                if not bool(row[2]):
                    continue
                columns = tuple(
                    item[2] for item in connection.execute(
                        f'PRAGMA index_info("{row[1]}")'
                    )
                )
                actual_unique.add(columns)

            expected_unique = {
                tuple(column.name for column in constraint.columns)
                for constraint in table.constraints
                if constraint.__class__.__name__ == "UniqueConstraint"
            }
            expected_unique.update(
                tuple(column.name for column in index.columns)
                for index in table.indexes if index.unique
            )
            if not expected_unique <= actual_unique:
                failures.append(
                    f"{table_name}: missing unique keys "
                    f"{sorted(expected_unique - actual_unique)!r}"
                )

    assert not failures, "\n".join(failures)


def test_all_domain_tables_and_indexes_compile_for_postgresql_17():
    dialect = postgresql.dialect(server_version_info=(17, 0))
    failures = []

    for table_name, table in metadata.tables.items():
        try:
            ddl = str(CreateTable(table).compile(dialect=dialect))
        except Exception as exc:  # compile every table to expose unsupported DDL
            failures.append(f"{table_name}: CREATE TABLE compilation failed: {exc}")
            continue

        for constraint in table.constraints:
            if isinstance(constraint, CheckConstraint) and not constraint.name:
                failures.append(f"{table_name}: unnamed CHECK constraint")
            if constraint.name and len(constraint.name) > 63:
                failures.append(
                    f"{table_name}: constraint name exceeds PostgreSQL limit: "
                    f"{constraint.name}"
                )

        if "CREATE TABLE" not in ddl:
            failures.append(f"{table_name}: PostgreSQL CREATE TABLE DDL missing")

        for index in table.indexes:
            if index.name and len(index.name) > 63:
                failures.append(
                    f"{table_name}: index name exceeds PostgreSQL limit: {index.name}"
                )
            try:
                index_ddl = str(CreateIndex(index).compile(dialect=dialect))
            except Exception as exc:
                failures.append(
                    f"{table_name}.{index.name}: CREATE INDEX compilation failed: {exc}"
                )
                continue
            if "CREATE " not in index_ddl or " INDEX " not in index_ddl:
                failures.append(f"{table_name}.{index.name}: invalid index DDL")

    assert not failures, "\n".join(failures)


def test_json_text_checks_compile_to_native_validity_predicates():
    scopes = metadata.tables["iam_access_tokens"].constraints
    metadata_json = metadata.tables["iam_security_events"].constraints
    scopes_check = next(
        item for item in scopes
        if isinstance(item, CheckConstraint) and item.name == "ck_iam_access_tokens_scopes_json_valid"
    )
    metadata_check = next(
        item for item in metadata_json
        if isinstance(item, CheckConstraint) and item.name == "ck_iam_security_events_metadata_json_valid"
    )

    sqlite_scopes = str(scopes_check.sqltext.compile(dialect=sqlite.dialect()))
    pg_scopes = str(scopes_check.sqltext.compile(dialect=postgresql.dialect()))
    sqlite_metadata = str(metadata_check.sqltext.compile(dialect=sqlite.dialect()))
    pg_metadata = str(metadata_check.sqltext.compile(dialect=postgresql.dialect()))

    assert "json_valid(scopes_json)" in sqlite_scopes
    assert "(scopes_json)::jsonb IS NOT NULL" in pg_scopes
    assert "json_valid(metadata_json)" in sqlite_metadata
    assert "(metadata_json)::jsonb IS NOT NULL" in pg_metadata
