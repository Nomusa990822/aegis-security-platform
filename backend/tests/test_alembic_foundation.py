"""Tests for the staged Alembic migration foundation."""
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import MetaData, Table, Column, Integer

from app.db_migrations.guard import assert_autogenerate_metadata_complete
from app.db_schema import metadata as aegis_metadata

BACKEND_ROOT = Path(__file__).resolve().parents[1]


def test_alembic_configuration_uses_repository_migration_directory():
    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    script_directory = ScriptDirectory.from_config(config)
    assert Path(script_directory.dir).resolve() == (BACKEND_ROOT / "alembic").resolve()
    assert config.get_main_option("sqlalchemy.url") == ""


def test_alembic_has_no_initial_or_implicit_baseline():
    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    assert ScriptDirectory.from_config(config).get_heads() == []


def test_all_domain_metadata_is_complete_for_autogeneration():
    assert aegis_metadata.tables
    assert not [
        table.name for table in aegis_metadata.tables.values()
        if table.info.get("reference_only") is True
    ]
    assert_autogenerate_metadata_complete(aegis_metadata)


def test_autogenerate_guard_accepts_complete_metadata():
    metadata = MetaData()
    Table("complete_example", metadata, Column("id", Integer, primary_key=True))
    assert_autogenerate_metadata_complete(metadata)
