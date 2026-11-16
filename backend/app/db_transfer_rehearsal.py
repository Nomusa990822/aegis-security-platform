"""Synthetic-only, transactional SQLAlchemy table transfer rehearsal."""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sqlalchemy import Table, func, insert, inspect, select


def _assert_synthetic_connections(source: Any, destination: Any) -> None:
    source_engine = source.engine
    destination_engine = destination.engine
    source_url = source_engine.url
    destination_url = destination_engine.url

    if source_url.drivername != "sqlite" or source_url.database != ":memory:":
        raise ValueError("synthetic transfer requires an in-memory SQLite source")
    if destination_url.drivername == "sqlite":
        if destination_url.database != ":memory:":
            raise ValueError("synthetic transfer requires an in-memory SQLite destination")
    elif destination_url.drivername == "postgresql+psycopg":
        database = (destination_url.database or "").lower()
        if not any(marker in database for marker in ("test", "rehearsal")):
            raise ValueError("PostgreSQL destination database must be explicitly test/rehearsal named")
    else:
        raise ValueError("unsupported synthetic transfer destination dialect")


def _verify_response_audit_integrity(connection: Any, tables: Sequence[Table]) -> None:
    """Verify canonical response hash chains and their persisted chain heads."""
    import json

    from app.response.audit_chain import verify_hash_chain

    by_name = {table.name: table for table in tables}
    audit = by_name.get("response_audit_log")
    heads = by_name.get("response_audit_chain_heads")
    if audit is None or heads is None:
        return

    events_by_response: dict[int, list[dict[str, Any]]] = {}
    rows = connection.execute(
        select(audit).order_by(audit.c.response_id, audit.c.id)
    ).mappings()
    for row in rows:
        event = dict(row)
        try:
            details = json.loads(event["details"])
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError(
                f"response audit event {event.get('id')} has invalid details JSON"
            ) from exc
        if not isinstance(details, dict):
            raise ValueError(
                f"response audit event {event.get('id')} details must be a JSON object"
            )
        event["details"] = details
        events_by_response.setdefault(event["response_id"], []).append(event)

    head_rows = {
        row["response_id"]: dict(row)
        for row in connection.execute(select(heads)).mappings()
    }
    if set(events_by_response) != set(head_rows):
        raise ValueError("response audit events and chain-head response IDs do not match")

    for response_id, events in events_by_response.items():
        result = verify_hash_chain(events)
        if not result["valid"]:
            raise ValueError(
                f"response audit chain {response_id} is invalid: "
                + "; ".join(result["errors"])
            )
        head = head_rows[response_id]
        if head["event_count"] != result["event_count"]:
            raise ValueError(
                f"response audit chain-head event count mismatch for response {response_id}"
            )
        if head["final_hash"] != result["final_hash"]:
            raise ValueError(
                f"response audit chain-head final hash mismatch for response {response_id}"
            )


def transfer_synthetic_tables(
    source_connection: Any,
    destination_connection: Any,
    tables: Sequence[Table],
    *,
    destination_schema: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Copy selected tables atomically and reconcile their contents.

    Connections must already be open. This function never creates engines,
    reads application configuration, runs DDL, or commits a caller-owned
    transaction. Both connections must be idle; destination is restricted to
    a test/rehearsal database and source to in-memory SQLite.
    """
    from app.db_transfer import dependency_order, digest_table_rows

    _assert_synthetic_connections(source_connection, destination_connection)
    if source_connection.in_transaction() or destination_connection.in_transaction():
        raise ValueError("transfer requires idle source and destination connections")

    ordered_names = dependency_order(tables)
    _verify_response_audit_integrity(source_connection, tables)
    by_name = {table.name: table for table in tables}
    manifest: dict[str, dict[str, Any]] = {}

    # Validate that the caller created the expected destination schema first.
    destination_inspector = inspect(destination_connection.engine)
    for name in ordered_names:
        table = by_name[name]
        inspected_schema = destination_schema if destination_schema is not None else table.schema
        if not destination_inspector.has_table(name, schema=inspected_schema):
            raise ValueError(f"destination table {name!r} is missing; DDL is never run by transfer")

    with destination_connection.begin():
        for name in ordered_names:
            table = by_name[name]
            source_rows = [
                dict(row._mapping)
                for row in source_connection.execute(
                    select(table).order_by(*tuple(table.primary_key.columns))
                )
            ]
            source_digest = digest_table_rows(table, source_rows)

            if source_rows:
                destination_connection.execute(insert(table), source_rows)

            destination_rows = [
                dict(row._mapping)
                for row in destination_connection.execute(
                    select(table).order_by(*tuple(table.primary_key.columns))
                )
            ]
            destination_digest = digest_table_rows(table, destination_rows)
            if len(source_rows) != len(destination_rows):
                raise ValueError(f"row-count reconciliation failed for {name}")
            if source_digest != destination_digest:
                raise ValueError(f"content reconciliation failed for {name}")

            manifest[name] = {
                "row_count": len(source_rows),
                "sha256": source_digest,
                "verified": True,
            }

        # Advance PostgreSQL serial/identity sequences past explicitly copied
        # integer primary keys. Non-integer and non-identity keys are untouched.
        if destination_connection.dialect.name == "postgresql":
            for table in tables:
                for column in table.primary_key.columns:
                    if not isinstance(column.type.python_type, type) or column.type.python_type is not int:
                        continue
                    if column.autoincrement is False:
                        continue
                    table_name = f"{destination_schema}.{table.name}" if destination_schema else table.fullname
                    sequence = destination_connection.execute(
                        select(func.pg_get_serial_sequence(table_name, column.name))
                    ).scalar_one_or_none()
                    if not sequence:
                        continue
                    maximum = destination_connection.execute(
                        select(func.max(column)).select_from(table)
                    ).scalar_one_or_none()
                    if maximum is not None:
                        destination_connection.execute(
                            select(func.setval(sequence, maximum, maximum > 0))
                        )

    _verify_response_audit_integrity(destination_connection, tables)

    return manifest
