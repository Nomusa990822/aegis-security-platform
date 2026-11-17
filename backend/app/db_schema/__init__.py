"""Shared SQLAlchemy Core metadata for the staged AEGIS schema.

Import domain modules before Alembic autogeneration so every table is registered.
This metadata is descriptive only; it is not used by application startup.
"""
from sqlalchemy import MetaData

metadata = MetaData(naming_convention={
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
})

# Register every domain before Alembic inspects target_metadata.
from app.db_schema import operational as _operational  # noqa: E402,F401
from app.db_schema import iam as _iam  # noqa: E402,F401
from app.db_schema import response as _response  # noqa: E402,F401
from app.db_schema import intelligence as _intelligence  # noqa: E402,F401
