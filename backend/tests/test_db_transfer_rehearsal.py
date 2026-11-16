"""Synthetic-only transactional database transfer rehearsal tests."""
from __future__ import annotations

import pytest
from sqlalchemy import Column, ForeignKey, Integer, MetaData, String, Table, create_engine, insert, select

from app.db_transfer_rehearsal import transfer_synthetic_tables


def _tables():
    metadata = MetaData()
    parents = Table(
        "synthetic_parents", metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("label", String(80), nullable=False),
    )
    children = Table(
        "synthetic_children", metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("parent_id", Integer, ForeignKey("synthetic_parents.id"), nullable=False),
        Column("payload", String(120), nullable=True),
    )
    return metadata, parents, children


def test_synthetic_transfer_copies_rows_and_reconciles_exact_values():
    metadata, parents, children = _tables()
    source_engine = create_engine("sqlite:///:memory:")
    destination_engine = create_engine("sqlite:///:memory:")
    try:
        metadata.create_all(source_engine)
        metadata.create_all(destination_engine)
        with source_engine.begin() as source:
            source.execute(insert(parents), [{"id": 4, "label": "parent café"}])
            source.execute(insert(children), [
                {"id": 11, "parent_id": 4, "payload": None},
                {"id": 19, "parent_id": 4, "payload": ""},
            ])
        with source_engine.connect() as source, destination_engine.connect() as destination:
            manifest = transfer_synthetic_tables(source, destination, [children, parents])
        assert manifest["synthetic_parents"]["row_count"] == 1
        assert manifest["synthetic_children"]["row_count"] == 2
        assert all(item["verified"] for item in manifest.values())
        with destination_engine.connect() as destination:
            copied = destination.execute(
                select(children).order_by(children.c.id)
            ).mappings().all()
            assert [(row["id"], row["parent_id"], row["payload"]) for row in copied] == [
                (11, 4, None), (19, 4, "")
            ]
    finally:
        source_engine.dispose()
        destination_engine.dispose()


def test_synthetic_transfer_rolls_back_all_tables_on_duplicate_destination_key():
    metadata, parents, children = _tables()
    source_engine = create_engine("sqlite:///:memory:")
    destination_engine = create_engine("sqlite:///:memory:")
    try:
        metadata.create_all(source_engine)
        metadata.create_all(destination_engine)
        with source_engine.begin() as source:
            source.execute(insert(parents), [{"id": 1, "label": "source"}])
            source.execute(insert(children), [{"id": 2, "parent_id": 1, "payload": "child"}])
        with destination_engine.begin() as destination:
            destination.execute(insert(parents), [{"id": 1, "label": "conflicting destination"}])
        with source_engine.connect() as source, destination_engine.connect() as destination:
            with pytest.raises(Exception):
                transfer_synthetic_tables(source, destination, [parents, children])
        with destination_engine.connect() as destination:
            assert destination.execute(select(parents)).mappings().all()[0]["label"] == "conflicting destination"
            assert destination.execute(select(children)).all() == []
    finally:
        source_engine.dispose()
        destination_engine.dispose()


def test_transfer_rejects_file_backed_sqlite_source():
    metadata, parents, _ = _tables()
    file_engine = create_engine("sqlite:///should-not-be-used.db")
    destination_engine = create_engine("sqlite:///:memory:")
    try:
        metadata.create_all(destination_engine)
        with file_engine.connect() as source, destination_engine.connect() as destination:
            with pytest.raises(ValueError, match="in-memory SQLite source"):
                transfer_synthetic_tables(source, destination, [parents])
    finally:
        file_engine.dispose()
        destination_engine.dispose()


def test_transfer_rejects_non_empty_destination_before_partial_copy():
    metadata, parents, _ = _tables()
    source_engine = create_engine("sqlite:///:memory:")
    destination_engine = create_engine("sqlite:///:memory:")
    try:
        metadata.create_all(source_engine)
        metadata.create_all(destination_engine)
        with source_engine.begin() as source:
            source.execute(insert(parents), [{"id": 1, "label": "source"}])
        with destination_engine.begin() as destination:
            destination.execute(insert(parents), [{"id": 1, "label": "already present"}])
        with source_engine.connect() as source, destination_engine.connect() as destination:
            with pytest.raises(Exception):
                transfer_synthetic_tables(source, destination, [parents])
        with destination_engine.connect() as destination:
            assert destination.execute(select(parents)).mappings().all()[0]["label"] == "already present"
    finally:
        source_engine.dispose()
        destination_engine.dispose()
