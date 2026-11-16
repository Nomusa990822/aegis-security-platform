"""Initial AEGIS PostgreSQL domain-schema baseline.

Revision ID: 20261117_01
Revises:
Create Date: 2026-11-17

This baseline is intentionally restricted to an empty, isolated database
schema. Existing installations must complete the separately documented
parity review before adopting this revision; do not run it over live tables.
"""
from __future__ import annotations

from alembic import op

from app.db_migrations.guard import assert_autogenerate_metadata_complete
from app.db_schema import metadata

revision = "20261117_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create the complete reviewed domain schema in an empty schema."""
    assert_autogenerate_metadata_complete(metadata)
    # checkfirst=False is deliberate: a non-empty target must fail closed.
    metadata.create_all(bind=op.get_bind(), checkfirst=False)


def downgrade() -> None:
    """Drop only the domain tables represented by this baseline."""
    assert_autogenerate_metadata_complete(metadata)
    metadata.drop_all(bind=op.get_bind(), checkfirst=False)
