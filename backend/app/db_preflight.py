"""Explicit-path, read-only SQLite schema preflight for migration planning.

This module never reads application configuration and never opens a default
application database. Callers must provide an existing regular SQLite file.
Only schema metadata and SQLite integrity diagnostics are inspected; row
contents and secret-bearing values are never selected.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import quote

from sqlalchemy import Float, Integer, LargeBinary, Text

from app.db_schema import metadata


def _sqlite_affinity(declared_type: str) -> str:
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


def _model_affinity(column: Any) -> str:
    if isinstance(column.type, Integer):
        return "INTEGER"
    if isinstance(column.type, LargeBinary):
        return "BLOB"
    if isinstance(column.type, Text):
        return "TEXT"
    if isinstance(column.type, Float):
        return "REAL"
    return "UNREVIEWED"


def _normalise_default(value: Any) -> str | None:
    if value is None or str(value).strip().upper() == "NULL":
        return None
    value = str(value).strip()
    while len(value) > 1 and value[0] == "(" and value[-1] == ")":
        value = value[1:-1].strip()
    if len(value) > 1 and value[0] in ("'", '"') and value[-1] == value[0]:
        value = value[1:-1]
    return value.lower()


def inspect_sqlite_schema_read_only(
    database_path: str | Path,
) -> dict[str, Any]:
    """Inspect schema compatibility without writing or reading table rows.

    The path is mandatory and must identify an existing, non-symlink regular
    file. SQLite is opened with mode=ro and query_only enabled. This function
    does not run migrations, create files, access application configuration,
    or expose table data.
    """
    supplied_path = Path(database_path).expanduser()
    if supplied_path.is_symlink():
        raise ValueError("SQLite preflight refuses symbolic-link paths")
    if not supplied_path.is_file():
        raise ValueError("SQLite preflight requires an existing regular file")
    resolved = supplied_path.resolve(strict=True)
    uri = f"file:{quote(resolved.as_posix(), safe='/')}?mode=ro"

    findings: list[dict[str, str]] = []
    table_report: dict[str, Any] = {}
    with sqlite3.connect(uri, uri=True) as connection:
        connection.execute("PRAGMA query_only = ON")
        integrity = connection.execute("PRAGMA quick_check").fetchall()
        fk_violations = connection.execute("PRAGMA foreign_key_check").fetchall()
        actual_tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        expected_tables = set(metadata.tables)
        for name in sorted(expected_tables - actual_tables):
            findings.append({"severity": "error", "code": "missing_table", "object": name})
        for name in sorted(actual_tables - expected_tables):
            findings.append({"severity": "warning", "code": "unmodelled_table", "object": name})

        for table_name in sorted(expected_tables & actual_tables):
            table = metadata.tables[table_name]
            actual_columns = {
                row[1]: row
                for row in connection.execute(f'PRAGMA table_info("{table_name}")')
            }
            expected_columns = set(table.columns.keys())
            for name in sorted(expected_columns - set(actual_columns)):
                findings.append({
                    "severity": "error", "code": "missing_column",
                    "object": f"{table_name}.{name}",
                })
            for name in sorted(set(actual_columns) - expected_columns):
                findings.append({
                    "severity": "warning", "code": "unmodelled_column",
                    "object": f"{table_name}.{name}",
                })

            column_results = {}
            for column in table.columns:
                row = actual_columns.get(column.name)
                if row is None:
                    continue
                actual_affinity = _sqlite_affinity(row[2])
                expected_affinity = _model_affinity(column)
                actual_default = _normalise_default(row[4])
                expected_default = _normalise_default(
                    column.server_default.arg
                    if column.server_default is not None else None
                )
                checks = {
                    "type_affinity_match": actual_affinity == expected_affinity,
                    "primary_key_match": (row[5] > 0) == column.primary_key,
                    "nullability_match": (
                        True if column.primary_key
                        else bool(row[3]) == (not column.nullable)
                    ),
                    "default_match": actual_default == expected_default,
                }
                column_results[column.name] = {
                    "sqlite_affinity": actual_affinity,
                    "model_affinity": expected_affinity,
                    **checks,
                }
                for check, passed in checks.items():
                    if not passed:
                        findings.append({
                            "severity": "error", "code": check,
                            "object": f"{table_name}.{column.name}",
                        })

            indexes = []
            for row in connection.execute(f'PRAGMA index_list("{table_name}")'):
                index_name = row[1]
                index_columns = [
                    item[2] for item in connection.execute(
                        f'PRAGMA index_info("{index_name}")'
                    )
                ]
                indexes.append({
                    "name": index_name,
                    "unique": bool(row[2]),
                    "partial": bool(row[4]),
                    "columns": index_columns,
                })
            table_report[table_name] = {
                "columns": column_results,
                "indexes": indexes,
            }

        if integrity != [("ok",)]:
            findings.append({
                "severity": "error", "code": "sqlite_quick_check",
                "object": "; ".join(str(row[0]) for row in integrity),
            })
        if fk_violations:
            findings.append({
                "severity": "error", "code": "foreign_key_violations",
                "object": str(len(fk_violations)),
            })

    return {
        "source": "explicit read-only SQLite path",
        "database_path": str(resolved),
        "integrity_check": "ok" if integrity == [("ok",)] else "failed",
        "foreign_key_violations": len(fk_violations),
        "expected_table_count": len(metadata.tables),
        "actual_table_count": len(actual_tables),
        "tables": table_report,
        "findings": findings,
        "compatible_for_baseline": not any(
            item["severity"] == "error" for item in findings
        ),
        "limitations": [
            "Schema-only inspection; no application rows are read.",
            "Check-constraint SQL, trigger bodies, collation, generated columns, and external audit checkpoints require separate review.",
            "A compatible report does not authorize migration or prove a backup is restorable.",
        ],
    }
