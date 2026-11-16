"""SQLAlchemy engine factory for the staged PostgreSQL transition.

The existing application continues to use its SQLite DB-API boundary until
repositories have been migrated. This module is additive and is not imported
by the application lifespan yet.
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

from sqlalchemy import Engine, create_engine
from sqlalchemy.engine import make_url
from psycopg.rows import dict_row


DATABASE_URL_ENV = "AEGIS_DATABASE_URL"
DEFAULT_CONNECT_TIMEOUT_SECONDS = 5
DEFAULT_POOL_SIZE = 5
DEFAULT_MAX_OVERFLOW = 10


def create_database_engine(
    database_url: str | None = None,
    *,
    engine_options: Mapping[str, Any] | None = None,
) -> Engine:
    """Create an explicitly configured SQLAlchemy 2.x engine.

    PostgreSQL connections must use psycopg 3 via the
    postgresql+psycopg URL scheme. SQLite URLs are accepted for isolated
    compatibility tests only; production configuration must use PostgreSQL.
    No connection is opened until the returned engine is first used.
    """
    url_value = database_url or os.getenv(DATABASE_URL_ENV)
    if not url_value:
        raise ValueError(f"{DATABASE_URL_ENV} must be configured")

    try:
        url = make_url(url_value)
    except Exception as exc:
        raise ValueError("Database URL is invalid") from exc

    if url.drivername not in {"postgresql+psycopg", "sqlite"}:
        raise ValueError(
            "Database URL must use postgresql+psycopg or sqlite"
        )

    options: dict[str, Any] = {
        "pool_pre_ping": True,
    }
    if url.drivername == "postgresql+psycopg":
        options.update(
            pool_size=DEFAULT_POOL_SIZE,
            max_overflow=DEFAULT_MAX_OVERFLOW,
            connect_args={
                "connect_timeout": DEFAULT_CONNECT_TIMEOUT_SECONDS,
                "row_factory": dict_row,
            },
        )
    if engine_options:
        options.update(dict(engine_options))

    return create_engine(url, **options)
