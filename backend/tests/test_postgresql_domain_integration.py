"""Real PostgreSQL integration tests for the staged AEGIS domain schema.

Every test owns a random schema and drops it after use. These tests never
connect to the production database or execute Alembic migrations.
"""
from __future__ import annotations

import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import MetaData, create_engine, inspect, select, text
from sqlalchemy.exc import IntegrityError

from app.db_engine import create_database_engine
from app.db_schema import metadata
from app.db_schema.iam import iam_mfa_factors, iam_users
from app.db_schema.intelligence import (
    ip_intelligence_assessments,
    ip_intelligence_provider_results,
)
from app.db_schema.operational import security_alerts
from app.db_schema.response import (
    response_audit_chain_heads,
    response_audit_log,
    response_records,
)


POSTGRES_URL = os.getenv("AEGIS_TEST_POSTGRES_URL")
EXPECTED_TABLES = set(metadata.tables)


@pytest.fixture()
def postgres_schema():
    if not POSTGRES_URL:
        pytest.skip("AEGIS_TEST_POSTGRES_URL is not configured")

    schema_name = f"aegis_integration_{uuid.uuid4().hex}"
    engine = create_database_engine(POSTGRES_URL)
    try:
        with engine.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema_name}"'))

        isolated_engine = engine.execution_options(
            schema_translate_map={None: schema_name}
        )
        metadata.create_all(isolated_engine)
        yield isolated_engine, engine, schema_name
    finally:
        with engine.begin() as connection:
            connection.execute(
                text(f'DROP SCHEMA IF EXISTS "{schema_name}" CASCADE')
            )
        engine.dispose()


def _insert_alert(connection, *, title="Integration test alert"):
    result = connection.execute(
        security_alerts.insert().values(
            title=title,
            severity="high",
            description="Synthetic PostgreSQL integration fixture",
            source_ip="198.51.100.24",
            detection_rule="TEST-POSTGRES-001",
            created_at="2026-11-16T12:00:00Z",
            status="open",
        )
    )
    return result.inserted_primary_key[0]


def _insert_user(connection, *, user_id=None, username="pg-analyst", normalized=None):
    user_id = user_id or str(uuid.uuid4())
    normalized = normalized or username
    connection.execute(
        iam_users.insert().values(
            id=user_id,
            username=username,
            username_normalized=normalized,
            role="analyst",
            status="active",
            created_at="2026-11-16T12:00:00Z",
            updated_at="2026-11-16T12:00:00Z",
        )
    )
    return user_id


def test_postgresql_creates_complete_domain_schema(postgres_schema):
    _, inspector_engine, schema_name = postgres_schema
    actual = set(inspect(inspector_engine).get_table_names(schema=schema_name))
    assert actual == EXPECTED_TABLES


def test_postgresql_enforces_foreign_keys_and_unique_relationships(postgres_schema):
    isolated_engine, _, _ = postgres_schema
    with isolated_engine.begin() as connection:
        alert_id = _insert_alert(connection)
        event_id = connection.execute(
            text(
                "INSERT INTO security_events "
                "(event_type, source_ip, occurred_at, received_at) "
                "VALUES ('authentication_failure', '198.51.100.24', "
                "'2026-11-16T12:00:00Z', '2026-11-16T12:00:01Z') RETURNING id"
            )
        ).scalar_one()

        connection.execute(
            text(
                "INSERT INTO incident_evidence "
                "(alert_id, event_id, linked_at) "
                "VALUES (:alert_id, :event_id, :linked_at)"
            ),
            {
                "alert_id": alert_id,
                "event_id": event_id,
                "linked_at": "2026-11-16T12:00:02Z",
            },
        )

    with pytest.raises(IntegrityError):
        with isolated_engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO incident_evidence "
                    "(alert_id, event_id, linked_at) "
                    "VALUES (:alert_id, :event_id, :linked_at)"
                ),
                {
                    "alert_id": alert_id,
                    "event_id": event_id,
                    "linked_at": "2026-11-16T12:00:03Z",
                },
            )

    with pytest.raises(IntegrityError):
        with isolated_engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO incident_evidence "
                    "(alert_id, event_id, linked_at) "
                    "VALUES (:alert_id, -999, '2026-11-16T12:00:04Z')"
                ),
            )


def test_postgresql_persists_encrypted_mfa_material_and_replay_state(postgres_schema):
    isolated_engine, _, _ = postgres_schema
    user_id = str(uuid.uuid4())
    factor_id = str(uuid.uuid4())
    ciphertext = bytes(range(32))

    with isolated_engine.begin() as connection:
        _insert_user(connection, user_id=user_id)
        connection.execute(
            iam_mfa_factors.insert().values(
                id=factor_id,
                user_id=user_id,
                factor_type="totp",
                secret_ciphertext=ciphertext,
                encryption_key_id="aegis-test-key-v1",
                status="active",
                last_accepted_step=59_000_000,
                created_at="2026-11-16T12:00:00Z",
                confirmed_at="2026-11-16T12:01:00Z",
            )
        )

    with isolated_engine.connect() as connection:
        row = connection.execute(
            select(iam_mfa_factors).where(iam_mfa_factors.c.id == factor_id)
        ).mappings().one()

    assert bytes(row["secret_ciphertext"]) == ciphertext
    assert row["encryption_key_id"] == "aegis-test-key-v1"
    assert row["last_accepted_step"] == 59_000_000
    assert row["status"] == "active"


def test_postgresql_enforces_concurrent_username_uniqueness(postgres_schema):
    isolated_engine, _, _ = postgres_schema
    barrier = threading.Barrier(2)
    normalized_username = f"race-{uuid.uuid4().hex[:16]}"

    def insert_user(index):
        user_id = str(uuid.uuid4())
        barrier.wait(timeout=10)
        try:
            with isolated_engine.begin() as connection:
                _insert_user(
                    connection,
                    user_id=user_id,
                    username=f"analyst-{index}",
                    normalized=normalized_username,
                )
            return "inserted"
        except IntegrityError:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(insert_user, (1, 2)))

    assert sorted(outcomes) == ["conflict", "inserted"]
    with isolated_engine.connect() as connection:
        count = connection.execute(
            select(text("COUNT(*)")).select_from(iam_users).where(
                iam_users.c.username_normalized == normalized_username
            )
        ).scalar_one()
    assert count == 1


def test_postgresql_intelligence_relationships_and_cascade(postgres_schema):
    isolated_engine, _, _ = postgres_schema
    with isolated_engine.begin() as connection:
        alert_id = _insert_alert(connection)
        assessment_id = connection.execute(
            ip_intelligence_assessments.insert()
            .values(
                ip_address="198.51.100.24",
                classification="suspicious",
                is_global=1,
                enrichment_status="complete",
                threat_score=82,
                confidence=0.91,
                reputation="malicious",
                categories='["botnet"]',
                assessed_at="2026-11-16T12:00:00Z",
                created_at="2026-11-16T12:00:00Z",
                alert_id=alert_id,
            )
            .returning(ip_intelligence_assessments.c.id)
        ).scalar_one()
        connection.execute(
            ip_intelligence_provider_results.insert().values(
                assessment_id=assessment_id,
                provider="synthetic-provider",
                status="success",
                reputation="malicious",
                confidence=0.91,
                categories='["botnet"]',
                details='{"source":"integration-test"}',
                checked_at="2026-11-16T12:00:00Z",
            )
        )

    with isolated_engine.begin() as connection:
        connection.execute(
            ip_intelligence_assessments.delete().where(
                ip_intelligence_assessments.c.id == assessment_id
            )
        )

    with isolated_engine.connect() as connection:
        remaining = connection.execute(
            select(ip_intelligence_provider_results.c.id).where(
                ip_intelligence_provider_results.c.assessment_id == assessment_id
            )
        ).all()
    assert remaining == []


def test_postgresql_audit_chain_append_and_rollback_are_atomic(postgres_schema):
    isolated_engine, _, _ = postgres_schema

    with pytest.raises(RuntimeError, match="rollback audit transaction"):
        with isolated_engine.begin() as connection:
            alert_id = _insert_alert(connection, title="Rolled-back audit fixture")
            response_id = connection.execute(
                response_records.insert()
                .values(
                    alert_id=alert_id,
                    action="block_ip",
                    target="198.51.100.24",
                    mode="dry_run",
                    requested_by="integration-analyst",
                    status="simulated",
                    policy_allowed=1,
                    approval_required=1,
                    executed=0,
                    simulated=1,
                    reasons="['integration test']",
                    created_at="2026-11-16T12:00:00Z",
                )
                .returning(response_records.c.id)
            ).scalar_one()
            connection.execute(
                response_audit_log.insert().values(
                    response_id=response_id,
                    alert_id=alert_id,
                    event="response_simulated",
                    actor="integration-analyst",
                    details='{"mode":"dry_run"}',
                    created_at="2026-11-16T12:00:01Z",
                    previous_hash="0" * 64,
                    event_hash="a" * 64,
                )
            )
            connection.execute(
                response_audit_chain_heads.insert().values(
                    response_id=response_id,
                    event_count=1,
                    final_hash="a" * 64,
                    updated_at="2026-11-16T12:00:01Z",
                )
            )
            raise RuntimeError("rollback audit transaction")

    with isolated_engine.connect() as connection:
        assert connection.execute(select(response_records.c.id)).all() == []
        assert connection.execute(select(response_audit_log.c.id)).all() == []
        assert connection.execute(select(response_audit_chain_heads.c.response_id)).all() == []

    with isolated_engine.begin() as connection:
        alert_id = _insert_alert(connection, title="Committed audit fixture")
        response_id = connection.execute(
            response_records.insert()
            .values(
                alert_id=alert_id,
                action="block_ip",
                target="198.51.100.24",
                mode="dry_run",
                requested_by="integration-analyst",
                status="simulated",
                policy_allowed=1,
                approval_required=1,
                executed=0,
                simulated=1,
                reasons="['integration test']",
                created_at="2026-11-16T12:02:00Z",
            )
            .returning(response_records.c.id)
        ).scalar_one()
        connection.execute(
            response_audit_log.insert().values(
                response_id=response_id,
                alert_id=alert_id,
                event="response_simulated",
                actor="integration-analyst",
                details='{"mode":"dry_run"}',
                created_at="2026-11-16T12:02:01Z",
                previous_hash="0" * 64,
                event_hash="b" * 64,
            )
        )
        connection.execute(
            response_audit_chain_heads.insert().values(
                response_id=response_id,
                event_count=1,
                final_hash="b" * 64,
                updated_at="2026-11-16T12:02:01Z",
            )
        )

    with isolated_engine.connect() as connection:
        event_hash = connection.execute(
            select(response_audit_log.c.event_hash).where(
                response_audit_log.c.response_id == response_id
            )
        ).scalar_one()
        head_hash = connection.execute(
            select(response_audit_chain_heads.c.final_hash).where(
                response_audit_chain_heads.c.response_id == response_id
            )
        ).scalar_one()

    assert event_hash == head_hash == "b" * 64
