"""PostgreSQL execution tests for the initial Alembic baseline."""
from __future__ import annotations

import os
import uuid

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url

from app.db_schema import metadata

BACKEND_ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]
POSTGRES_URL_ENV = "AEGIS_TEST_POSTGRES_URL"


@pytest.mark.skipif(
    not os.getenv(POSTGRES_URL_ENV),
    reason="PostgreSQL service URL is not configured",
)
def test_baseline_upgrade_and_downgrade_in_disposable_schema(monkeypatch):
    """Run the actual Alembic revision against an isolated PostgreSQL schema."""
    schema = f"aegis_baseline_{uuid.uuid4().hex[:12]}"
    base_url = make_url(os.environ[POSTGRES_URL_ENV])
    admin_engine = create_engine(base_url)

    try:
        with admin_engine.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))

        isolated_url = base_url.update_query_dict(
            {"options": f"-csearch_path={schema}"}
        )
        monkeypatch.setenv("AEGIS_DATABASE_URL", str(isolated_url))
        monkeypatch.setenv("AEGIS_ALEMBIC_ALLOW_MIGRATIONS", "1")

        config = Config(str(BACKEND_ROOT / "alembic.ini"))
        command.upgrade(config, "head")

        with admin_engine.connect() as connection:
            connection.execute(text(f'SET search_path TO "{schema}"'))
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
                assert len(inspector.get_indexes(table_name)) == len(table.indexes)

        command.downgrade(config, "base")

        with admin_engine.connect() as connection:
            connection.execute(text(f'SET search_path TO "{schema}"'))
            remaining = set(inspect(connection).get_table_names())
            assert remaining <= {"alembic_version"}
    finally:
        with admin_engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        admin_engine.dispose()
