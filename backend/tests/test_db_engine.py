import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from app.db_engine import create_database_engine


def test_engine_requires_explicit_database_url(monkeypatch):
    monkeypatch.delenv("AEGIS_DATABASE_URL", raising=False)

    with pytest.raises(ValueError, match="AEGIS_DATABASE_URL"):
        create_database_engine()


def test_engine_rejects_unapproved_or_ambiguous_drivers():
    with pytest.raises(ValueError, match="postgresql\\+psycopg"):
        create_database_engine("postgresql://user:pass@localhost/aegis")

    with pytest.raises(ValueError, match="postgresql\\+psycopg"):
        create_database_engine("mysql+pymysql://user:pass@localhost/aegis")


def test_sqlite_engine_supports_explicit_transaction_rollback():
    engine = create_database_engine("sqlite://")

    try:
        with engine.begin() as connection:
            connection.execute(
                text("CREATE TABLE transaction_probe (value INTEGER NOT NULL)")
            )

        with pytest.raises(RuntimeError, match="rollback probe"):
            with engine.begin() as connection:
                connection.execute(
                    text("INSERT INTO transaction_probe (value) VALUES (1)")
                )
                raise RuntimeError("rollback probe")

        with engine.connect() as connection:
            count = connection.execute(
                text("SELECT COUNT(*) FROM transaction_probe")
            ).scalar_one()

        assert count == 0
    finally:
        engine.dispose()


def test_engine_does_not_connect_until_first_use():
    engine = create_database_engine("postgresql+psycopg://user:pass@127.0.0.1:1/aegis")

    try:
        assert engine.dialect.name == "postgresql"
        with pytest.raises(OperationalError):
            with engine.connect():
                pass
    finally:
        engine.dispose()
