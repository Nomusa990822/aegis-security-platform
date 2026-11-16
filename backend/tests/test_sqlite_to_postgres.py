from pathlib import Path
import sqlite3

import pytest
from sqlalchemy import create_engine

from app.db_schema import metadata
from app.sqlite_to_postgres import (
    CONFIRMATION,
    _backup_sqlite,
    _verify_source_schema,
    migrate,
)


def test_sqlite_backup_is_verified_and_source_is_unchanged(tmp_path):
    source = tmp_path / "aegis.db"
    backup = tmp_path / "backup.db"
    connection = sqlite3.connect(source)
    connection.execute("CREATE TABLE preserved (id INTEGER PRIMARY KEY, value TEXT)")
    connection.execute("INSERT INTO preserved (value) VALUES ('original')")
    connection.commit()
    connection.close()

    digest = _backup_sqlite(source, backup)

    assert len(digest) == 64
    assert backup.is_file()
    assert sqlite3.connect(source).execute(
        "SELECT value FROM preserved"
    ).fetchone()[0] == "original"
    assert sqlite3.connect(backup).execute(
        "SELECT value FROM preserved"
    ).fetchone()[0] == "original"


def test_sqlite_backup_refuses_to_overwrite_existing_file(tmp_path):
    source = tmp_path / "aegis.db"
    backup = tmp_path / "backup.db"
    sqlite3.connect(source).close()
    backup.write_text("do not overwrite")

    with pytest.raises(FileExistsError, match="Refusing to overwrite"):
        _backup_sqlite(source, backup)

    assert backup.read_text() == "do not overwrite"


def test_source_schema_guard_accepts_reviewed_baseline(tmp_path):
    source = create_engine(f"sqlite:///{tmp_path / 'source.db'}")
    try:
        metadata.create_all(source)
        with source.connect() as connection:
            _verify_source_schema(connection)
    finally:
        source.dispose()


def test_source_schema_guard_rejects_missing_domain_tables(tmp_path):
    source = create_engine(f"sqlite:///{tmp_path / 'source.db'}")
    try:
        with source.begin() as connection:
            connection.exec_driver_sql(
                "CREATE TABLE security_events (id INTEGER PRIMARY KEY)"
            )
        with source.connect() as connection:
            with pytest.raises(RuntimeError, match="missing required tables"):
                _verify_source_schema(connection)
    finally:
        source.dispose()


def test_transfer_requires_exact_operator_confirmation(tmp_path):
    source = tmp_path / "aegis.db"
    backup = tmp_path / "backup.db"
    sqlite3.connect(source).close()

    with pytest.raises(ValueError, match="Explicit confirmation required"):
        migrate(source, backup, "yes")

    assert not backup.exists()


def test_confirmation_phrase_is_explicit_and_stable():
    assert CONFIRMATION == "MIGRATE AEGIS SQLITE DATA TO POSTGRESQL"
