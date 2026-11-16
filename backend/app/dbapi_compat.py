"""Small DB-API compatibility layer for the PostgreSQL runtime.

The application repositories historically use sqlite3's execute/row API. This
adapter keeps that call contract while PostgreSQL-specific SQL is migrated
incrementally. It deliberately supports only the SQL constructs used by AEGIS;
it is not a general SQL dialect translator.
"""
from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.pq import TransactionStatus


_INSERT_TABLE = re.compile(r"^\s*INSERT\s+(?:OR\s+IGNORE\s+)?INTO\s+[\"]?([a-zA-Z_][\w]*)", re.I)
_AUTO_ID_TABLES = {
    "security_events", "security_alerts", "incident_notes", "incident_timeline",
    "incident_evidence", "alert_audit_log", "security_correlations",
    "security_correlation_alerts", "correlation_notes", "correlation_timeline",
    "correlation_audit_log", "ip_intelligence_assessments",
    "ip_intelligence_provider_results", "response_records", "response_audit_log",
    "iam_users", "iam_mfa_factors", "iam_recovery_codes", "iam_access_tokens",
    "iam_sessions", "iam_auth_challenges", "iam_activation_tokens",
    "iam_security_events",
}


def _qmark_to_pyformat(sql: str) -> str:
    """Translate positional qmark binds without touching quoted SQL strings."""
    result: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(sql):
        char = sql[i]
        if quote:
            result.append(char)
            if char == quote:
                if i + 1 < len(sql) and sql[i + 1] == quote:
                    result.append(sql[i + 1])
                    i += 1
                else:
                    quote = None
        elif char in {"'", '"'}:
            quote = char
            result.append(char)
        elif char == "?":
            result.append("%s")
        else:
            result.append(char)
        i += 1
    return "".join(result)


class HybridRow(dict):
    """Mapping row with sqlite3.Row-compatible integer indexing."""

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, int):
            try:
                key = tuple(self.keys())[key]
            except IndexError:
                raise IndexError(key) from None
        return super().__getitem__(key)


class PostgresCursor:
    def __init__(self, cursor, returned_row=None):
        self._cursor = cursor
        self._returned_row = returned_row

    @property
    def rowcount(self) -> int:
        return self._cursor.rowcount

    @property
    def lastrowid(self):
        return self._returned_row.get("id") if self._returned_row else None

    def fetchone(self):
        row = self._cursor.fetchone()
        return HybridRow(row) if row is not None else None

    def fetchall(self):
        return [HybridRow(row) for row in self._cursor.fetchall()]

    def __iter__(self):
        for row in self._cursor:
            yield HybridRow(row)


class PostgresConnection:
    """Connection wrapper implementing the subset of sqlite3.Connection used."""

    def __init__(self, raw_connection):
        self._raw = raw_connection

    def execute(self, sql: str, parameters: Sequence[Any] | None = None):
        statement = sql.strip()
        upper = statement.upper()

        if upper in {"BEGIN IMMEDIATE", "BEGIN EXCLUSIVE"}:
            if self._raw.info.transaction_status == TransactionStatus.IDLE:
                self._raw.execute("BEGIN")
            return PostgresCursor(self._raw.cursor())

        ignore_insert = bool(re.match(r"^INSERT\s+OR\s+IGNORE\s+INTO\b", statement, re.I))
        if ignore_insert:
            statement = re.sub(
                r"^INSERT\s+OR\s+IGNORE\s+INTO\b",
                "INSERT INTO",
                statement,
                count=1,
                flags=re.I,
            )
            if not re.search(r"\bON\s+CONFLICT\b", statement, re.I):
                statement = statement.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"

        insert_match = _INSERT_TABLE.match(statement)
        if insert_match and insert_match.group(1).lower() in _AUTO_ID_TABLES:
            if not re.search(r"\bRETURNING\b", statement, re.I):
                statement = statement.rstrip().rstrip(";") + " RETURNING id"

        statement = _qmark_to_pyformat(statement)
        cursor = self._raw.cursor()
        cursor.execute(statement, tuple(parameters or ()))

        returned_row = None
        if insert_match and re.search(r"\bRETURNING\s+id\s*$", statement, re.I):
            returned_row = cursor.fetchone()
        return PostgresCursor(cursor, returned_row)

    def commit(self):
        self._raw.commit()

    def rollback(self):
        self._raw.rollback()

    def close(self):
        self._raw.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            if exc_type is None:
                self.commit()
            else:
                self.rollback()
        finally:
            self.close()
        return False


def connect_postgres(database_url: str) -> PostgresConnection:
    """Open a psycopg 3 connection using mapping rows."""
    return PostgresConnection(psycopg.connect(database_url, row_factory=dict_row))
