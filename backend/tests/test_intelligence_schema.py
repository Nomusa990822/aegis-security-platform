"""Cross-dialect contract tests for the staged intelligence schema."""

import os
import uuid

import pytest
from sqlalchemy import create_engine, inspect, text

from app.db_schema.intelligence import (
    ip_intelligence_assessments,
    ip_intelligence_provider_results,
    metadata,
)


def _assert_intelligence_schema(engine, schema=None):
    inspector = inspect(engine)
    assessment_columns = {
        column["name"]
        for column in inspector.get_columns("ip_intelligence_assessments", schema=schema)
    }
    provider_columns = {
        column["name"]
        for column in inspector.get_columns("ip_intelligence_provider_results", schema=schema)
    }

    assert assessment_columns == {
        "id",
        "ip_address",
        "classification",
        "is_global",
        "enrichment_status",
        "threat_score",
        "confidence",
        "reputation",
        "categories",
        "first_seen",
        "last_seen",
        "assessed_at",
        "created_at",
        "alert_id",
    }
    assert provider_columns == {
        "id",
        "assessment_id",
        "provider",
        "status",
        "reputation",
        "confidence",
        "categories",
        "details",
        "error",
        "checked_at",
    }

    provider_foreign_keys = inspector.get_foreign_keys(
        "ip_intelligence_provider_results", schema=schema
    )
    assert any(
        fk["referred_table"] == "ip_intelligence_assessments"
        and fk["options"].get("ondelete") == "CASCADE"
        for fk in provider_foreign_keys
    )

    assessment_foreign_keys = inspector.get_foreign_keys(
        "ip_intelligence_assessments", schema=schema
    )
    assert any(
        fk["referred_table"] == "security_alerts"
        and fk["options"].get("ondelete") == "SET NULL"
        for fk in assessment_foreign_keys
    )


def test_intelligence_schema_creates_on_sqlite():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    try:
        metadata.create_all(engine)
        _assert_intelligence_schema(engine)
    finally:
        engine.dispose()


def test_intelligence_schema_preserves_existing_storage_contract():
    assert str(ip_intelligence_assessments.c.categories.type) == "TEXT"
    assert str(ip_intelligence_assessments.c.is_global.type) == "INTEGER"
    assert str(ip_intelligence_provider_results.c.details.type) == "TEXT"


def test_intelligence_schema_creates_in_isolated_postgresql_schema():
    database_url = os.getenv("AEGIS_TEST_POSTGRES_URL")
    if not database_url:
        pytest.skip("AEGIS_TEST_POSTGRES_URL is not configured")

    schema_name = f"aegis_schema_test_{uuid.uuid4().hex}"
    engine = create_engine(database_url, pool_pre_ping=True)
    try:
        with engine.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema_name}"'))

        isolated_engine = engine.execution_options(
            schema_translate_map={None: schema_name}
        )
        metadata.create_all(isolated_engine)
        _assert_intelligence_schema(engine, schema=schema_name)
    finally:
        with engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema_name}" CASCADE'))
        engine.dispose()
