"""PostgreSQL-backed synthetic transfer rehearsal integration test."""
from __future__ import annotations

import os
from uuid import uuid4

import pytest
from sqlalchemy import Column, ForeignKey, Integer, MetaData, String, Table, create_engine, insert, select

from app.db_transfer_rehearsal import transfer_synthetic_tables



@pytest.mark.skipif(
    not os.getenv("AEGIS_TEST_POSTGRES_URL"),
    reason="AEGIS_TEST_POSTGRES_URL is not configured",
)
def test_synthetic_sqlite_to_postgresql_transfer_preserves_ids_and_advances_sequence():
    schema = "aegis_transfer_test_" + uuid4().hex
    postgres_engine = create_engine(os.environ["AEGIS_TEST_POSTGRES_URL"])
    source_metadata = MetaData()
    parents = Table(
        "synthetic_parents", source_metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("label", String(80), nullable=False),
        schema=schema,
    )
    children = Table(
        "synthetic_children", source_metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("parent_id", Integer, ForeignKey(f"{schema}.synthetic_parents.id"), nullable=False),
        Column("payload", String(120), nullable=True),
        schema=schema,
    )
    source_engine = create_engine(
        "sqlite:///:memory:",
        execution_options={"schema_translate_map": {schema: None}},
    )
    try:
        with postgres_engine.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        source_metadata.create_all(source_engine)
        source_metadata.create_all(postgres_engine)

        with source_engine.begin() as source:
            source.execute(insert(parents), [{"id": 4, "label": "synthetic parent café"}])
            source.execute(insert(children), [
                {"id": 11, "parent_id": 4, "payload": None},
                {"id": 19, "parent_id": 4, "payload": ""},
            ])

        with source_engine.connect() as source, postgres_engine.connect() as destination:
            manifest = transfer_synthetic_tables(source, destination, [children, parents])

        assert manifest["synthetic_parents"]["row_count"] == 1
        assert manifest["synthetic_children"]["row_count"] == 2
        with postgres_engine.begin() as destination:
            rows = destination.execute(
                select(children).order_by(children.c.id)
            ).mappings().all()
            assert [(row["id"], row["parent_id"], row["payload"]) for row in rows] == [
                (11, 4, None), (19, 4, "")
            ]
            next_parent_id = destination.execute(
                insert(parents).values(label="sequence probe").returning(parents.c.id)
            ).scalar_one()
            assert next_parent_id > 4
    finally:
        with postgres_engine.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        source_engine.dispose()
        postgres_engine.dispose()
