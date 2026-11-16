"""Deterministic, side-effect-free primitives for synthetic DB transfer rehearsals.

This module does not open databases, copy records, run migrations, or access
application configuration. It only orders SQLAlchemy tables and hashes rows
already supplied by a caller.
"""
from __future__ import annotations

import hashlib
import math
import struct
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from sqlalchemy import Table


def _frame(tag: bytes, payload: bytes = b"") -> bytes:
    """Encode a typed value using a one-byte tag and an unsigned length."""
    if len(tag) != 1:
        raise ValueError("value tags must be exactly one byte")
    return tag + struct.pack(">Q", len(payload)) + payload


def encode_value(value: Any) -> bytes:
    """Encode SQLite/PostgreSQL scalar values without conflating their types."""
    if value is None:
        return _frame(b"N")
    if isinstance(value, bool):
        return _frame(b"B", b"1" if value else b"0")
    if isinstance(value, int):
        return _frame(b"I", str(value).encode("ascii"))
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite floats are not supported in transfer digests")
        # float.hex preserves the sign of zero and is independent of locale.
        return _frame(b"F", value.hex().encode("ascii"))
    if isinstance(value, str):
        return _frame(b"S", value.encode("utf-8"))
    if isinstance(value, (bytes, bytearray, memoryview)):
        return _frame(b"Y", bytes(value))
    raise TypeError(f"unsupported transfer digest value type: {type(value).__name__}")


def _hash_field(hasher: Any, payload: bytes) -> None:
    hasher.update(struct.pack(">Q", len(payload)))
    hasher.update(payload)


def digest_table_rows(table: Table, rows: Iterable[Mapping[str, Any]]) -> str:
    """Return a SHA-256 digest independent of input row iteration order.

    Rows are sorted by the canonical encoded primary-key tuple. Every metadata
    column participates in the digest in metadata order, including NULL values.
    A primary key is mandatory so duplicate/equal rows have an unambiguous key.
    """
    primary_key = tuple(table.primary_key.columns)
    if not primary_key:
        raise ValueError(f"table {table.name!r} has no primary key")

    column_names = tuple(column.name for column in table.columns)
    prepared: list[tuple[bytes, Mapping[str, Any]]] = []
    for row in rows:
        missing = set(column_names) - set(row)
        extra = set(row) - set(column_names)
        if missing or extra:
            raise ValueError(
                f"row shape mismatch for {table.name}: "
                f"missing={sorted(missing)}, extra={sorted(extra)}"
            )
        key = b"".join(encode_value(row[column.name]) for column in primary_key)
        prepared.append((key, row))

    prepared.sort(key=lambda item: item[0])
    hasher = hashlib.sha256()
    _hash_field(hasher, b"AEGIS-TRANSFER-TABLE-v1")
    _hash_field(hasher, table.name.encode("utf-8"))
    _hash_field(hasher, b"".join(
        _frame(b"C", name.encode("utf-8")) for name in column_names
    ))

    previous_key: bytes | None = None
    for key, row in prepared:
        if previous_key == key:
            raise ValueError(f"duplicate primary key in digest input for {table.name}")
        previous_key = key
        _hash_field(hasher, key)
        for name in column_names:
            _hash_field(hasher, encode_value(row[name]))
    return hasher.hexdigest()


def dependency_order(tables: Sequence[Table]) -> list[str]:
    """Return deterministic parent-before-child table order.

    Every referenced table must be included. Self-references do not create an
    ordering edge. Cycles are rejected instead of silently producing a partial
    order; callers must design an explicit deferrable-constraint strategy.
    """
    by_name = {table.name: table for table in tables}
    if len(by_name) != len(tables):
        raise ValueError("table names must be unique")

    dependencies: dict[str, set[str]] = {name: set() for name in by_name}
    dependents: dict[str, set[str]] = {name: set() for name in by_name}
    for child_name, table in by_name.items():
        for constraint in table.foreign_key_constraints:
            for element in constraint.elements:
                parent_name = element.column.table.name
                if parent_name == child_name:
                    continue
                if parent_name not in by_name:
                    raise ValueError(
                        f"referenced table {parent_name!r} for {child_name!r} "
                        "is not included in transfer set"
                    )
                dependencies[child_name].add(parent_name)
                dependents[parent_name].add(child_name)

    ready = sorted(name for name, required in dependencies.items() if not required)
    ordered: list[str] = []
    while ready:
        current = ready.pop(0)
        ordered.append(current)
        for child in sorted(dependents[current]):
            dependencies[child].discard(current)
            if not dependencies[child] and child not in ordered and child not in ready:
                ready.append(child)
        ready.sort()

    if len(ordered) != len(by_name):
        cyclic = sorted(name for name, required in dependencies.items() if required)
        raise ValueError(f"foreign-key dependency cycle detected: {cyclic}")
    return ordered
