"""Unit tests for deterministic, side-effect-free transfer primitives."""
from __future__ import annotations

import pytest
from sqlalchemy import Column, ForeignKey, Integer, MetaData, Table

from app.db_schema import metadata
from app.db_transfer import dependency_order, digest_table_rows, encode_value


def test_value_encoding_distinguishes_null_empty_and_scalar_types():
    encoded = {
        encode_value(None),
        encode_value(""),
        encode_value(b""),
        encode_value(0),
        encode_value(0.0),
        encode_value(False),
    }
    assert len(encoded) == 6


def test_value_encoding_preserves_text_and_binary_bytes():
    assert encode_value("café") != encode_value("cafe")
    assert encode_value(b"\\x00\\xff") != encode_value("\\x00\\xff")


def test_value_encoding_rejects_non_finite_and_unsupported_values():
    with pytest.raises(ValueError, match="non-finite"):
        encode_value(float("nan"))
    with pytest.raises(TypeError, match="unsupported"):
        encode_value(object())


def test_table_digest_is_independent_of_input_row_order():
    table = metadata.tables["security_events"]
    rows = [
        {
            "id": 9, "event_type": "login", "source_ip": None, "username": "u9",
            "outcome": "failure", "description": "", "occurred_at": "t9",
            "received_at": "t9", "destination_ip": None, "destination_port": None,
            "protocol": None, "source_system": None, "external_event_id": None,
        },
        {
            "id": 2, "event_type": "login", "source_ip": "198.51.100.2",
            "username": "u2", "outcome": "success", "description": "ok",
            "occurred_at": "t2", "received_at": "t2", "destination_ip": None,
            "destination_port": None, "protocol": None, "source_system": "sensor",
            "external_event_id": "evt-2",
        },
    ]
    assert digest_table_rows(table, rows) == digest_table_rows(table, reversed(rows))


def test_table_digest_changes_when_any_stored_value_changes():
    table = metadata.tables["iam_mfa_factors"]
    row = {
        column.name: None for column in table.columns
    }
    row.update({
        "id": "00000000-0000-4000-8000-000000000001",
        "user_id": "00000000-0000-4000-8000-000000000002",
        "factor_type": "totp",
        "secret_ciphertext": b"synthetic-ciphertext",
        "encryption_key_id": "synthetic-key",
        "status": "active",
        "created_at": "2026-01-01T00:00:00+00:00",
    })
    changed = dict(row, secret_ciphertext=b"changed-synthetic-ciphertext")
    assert digest_table_rows(table, [row]) != digest_table_rows(table, [changed])


def test_table_digest_rejects_duplicate_keys_and_incomplete_row_shapes():
    table = metadata.tables["security_alerts"]
    row = {
        "id": 1, "title": "test", "severity": "low", "description": "test",
        "source_ip": None, "detection_rule": "TEST", "created_at": "t", "status": "open",
    }
    with pytest.raises(ValueError, match="duplicate primary key"):
        digest_table_rows(table, [row, row])
    with pytest.raises(ValueError, match="row shape mismatch"):
        digest_table_rows(table, [{**row, "unexpected": "field"}])


def test_domain_dependency_order_places_parents_before_children():
    tables = list(metadata.tables.values())
    order = dependency_order(tables)
    positions = {name: index for index, name in enumerate(order)}
    assert set(order) == set(metadata.tables)
    for child in tables:
        for constraint in child.foreign_key_constraints:
            for element in constraint.elements:
                parent_name = element.column.table.name
                if parent_name != child.name:
                    assert positions[parent_name] < positions[child.name]


def test_dependency_order_is_deterministic():
    tables = list(metadata.tables.values())
    assert dependency_order(tables) == dependency_order(list(reversed(tables)))


def test_dependency_order_rejects_missing_parent():
    local = MetaData()
    parent = Table("parent", local, Column("id", Integer, primary_key=True))
    child = Table(
        "child", local,
        Column("id", Integer, primary_key=True),
        Column("parent_id", Integer, ForeignKey("parent.id")),
    )
    with pytest.raises(ValueError, match="not included"):
        dependency_order([child])


def test_dependency_order_rejects_cycles():
    local = MetaData()
    first = Table(
        "first", local,
        Column("id", Integer, primary_key=True),
        Column("second_id", Integer, ForeignKey("second.id")),
    )
    second = Table(
        "second", local,
        Column("id", Integer, primary_key=True),
        Column("first_id", Integer, ForeignKey("first.id")),
    )
    with pytest.raises(ValueError, match="cycle detected"):
        dependency_order([first, second])
