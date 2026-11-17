"""Alembic environment for the staged AEGIS PostgreSQL transition.

This is intentionally not invoked by FastAPI startup. Migration commands
require an explicit opt-in and a database URL supplied through the environment.
"""
from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context

from app.db_engine import create_database_engine
from app.db_migrations.guard import assert_autogenerate_metadata_complete
from app.db_schema.intelligence import metadata as target_metadata

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def _require_explicit_migration_opt_in() -> None:
    if os.getenv("AEGIS_ALEMBIC_ALLOW_MIGRATIONS") != "1":
        raise RuntimeError(
            "Alembic execution is disabled by default. Set "
            "AEGIS_ALEMBIC_ALLOW_MIGRATIONS=1 for an explicitly reviewed "
            "migration operation. This does not authorize production changes."
        )


def _guard_autogenerate() -> None:
    command_options = getattr(config, "cmd_opts", None)
    if getattr(command_options, "autogenerate", False):
        assert_autogenerate_metadata_complete(target_metadata)


def run_migrations_offline() -> None:
    _require_explicit_migration_opt_in()
    _guard_autogenerate()
    database_url = os.getenv("AEGIS_DATABASE_URL")
    if not database_url:
        raise RuntimeError("AEGIS_DATABASE_URL must be configured")

    context.configure(
        url=database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    _require_explicit_migration_opt_in()
    _guard_autogenerate()
    engine = create_database_engine()
    try:
        with engine.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                compare_type=True,
                compare_server_default=True,
                transaction_per_migration=True,
                render_as_batch=False,
            )
            with context.begin_transaction():
                context.run_migrations()
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
