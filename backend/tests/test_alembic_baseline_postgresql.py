"""PostgreSQL execution tests for the initial Alembic baseline."""
from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

from app.db_schema import metadata

BACKEND_ROOT = Path(__file__).resolve().parents[1]
POSTGRES_URL_ENV = "AEGIS_TEST_POSTGRES_URL"


@pytest.mark.skipif(
    not os.getenv(POSTGRES_URL_ENV),
    reason="PostgreSQL service URL is not configured",
)
def test_baseline_upgrade_and_downgrade_in_disposable_schema(monkeypatch):
    """Run the actual Alembic revision against an isolated PostgreSQL schema."""
    schema = f"aegis_baseline_{uuid.uuid4().hex[:12]}"
    admin_engine = create_engine(os.environ[POSTGRES_URL_ENV])

    try:
        with admin_engine.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))

        monkeypatch.setenv("AEGIS_DATABASE_URL", os.environ[POSTGRES_URL_ENV])
        monkeypatch.setenv("AEGIS_ALEMBIC_ALLOW_MIGRATIONS", "1")
        config = Config(str(BACKEND_ROOT / "alembic.ini"))

        # Reuse the known-good CI service connection. The session search_path
        # isolates every Alembic operation without rewriting URL credentials
        # or creating a second connection with altered query parameters.
        with admin_engine.connect() as connection:
            connection.execute(text(f'SET search_path TO "{schema}"'))
            connection.commit()
            config.attributes["connection"] = connection

            command.upgrade(config, "head")
            inspector = inspect(connection)
            actual_tables = set(inspector.get_table_names()) - {"alembic_version"}
            assert actual_tables == set(metadata.tables)
            assert len(actual_tables) == 27

            for table_name, table in metadata.tables.items():
                actual_columns = {
                    column["name"] for column in inspector.get_columns(table_name)
                }
                assert actual_columns == set(table.columns.keys())
                assert len(inspector.get_foreign_keys(table_name)) == len(
                    [item for item in table.foreign_key_constraints]
                )
                # PostgreSQL reports indexes backing UNIQUE constraints as
                # indexes too; SQLAlchemy models those as constraints, not
                # entries in Table.indexes. Exclude those duplicates here.
                actual_indexes = [
                    index
                    for index in inspector.get_indexes(table_name)
                    if index.get("duplicates_constraint") is None
                ]
                assert len(actual_indexes) == len(table.indexes)

            command.downgrade(config, "base")
            remaining = set(inspect(connection).get_table_names())
            assert remaining <= {"alembic_version"}
    finally:
        with admin_engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        admin_engine.dispose()
