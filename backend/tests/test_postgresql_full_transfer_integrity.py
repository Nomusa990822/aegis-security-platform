"""Full-domain synthetic SQLite-to-PostgreSQL integrity rehearsal."""
from __future__ import annotations

import json
import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, insert, select

from app.db_schema import metadata
from app.response.audit_chain import GENESIS_HASH, calculate_event_hash, verify_hash_chain
from app.db_transfer import dependency_order
from app.db_transfer_rehearsal import transfer_synthetic_tables


NOW = "2026-11-16T12:00:00+00:00"
USER_ID = "12345678-1234-4234-8234-123456789012"
MFA_ID = "22345678-1234-4234-8234-123456789012"
RECOVERY_ID = "32345678-1234-4234-8234-123456789012"
TOKEN_ID = "42345678-1234-4234-8234-123456789012"
SESSION_ID = "52345678-1234-4234-8234-123456789012"
CHALLENGE_ID = "62345678-1234-4234-8234-123456789012"
ACTIVATION_ID = "72345678-1234-4234-8234-123456789012"
IAM_EVENT_ID = "82345678-1234-4234-8234-123456789012"
ARGON_HASH = "$argon2id$v=19$m=19456,t=2,p=1$c3ludGhldGljLXNhbHQ$" + "a" * 32
FAKE_CIPHERTEXT = b"synthetic-only-aes-gcm-ciphertext\x00\x01"
AUDIT_HASH_1 = "1" * 64
AUDIT_HASH_2 = "2" * 64


def _value_for_column(table, column, parent_rows):
    if column.foreign_keys:
        fk = next(iter(column.foreign_keys))
        parent_table = fk.column.table.name
        return parent_rows[parent_table][fk.column.name]
    if column.primary_key:
        if column.name == "id" and column.type.python_type is str:
            return {
                "iam_users": USER_ID,
                "iam_mfa_factors": MFA_ID,
                "iam_recovery_codes": RECOVERY_ID,
                "iam_access_tokens": TOKEN_ID,
                "iam_sessions": SESSION_ID,
                "iam_auth_challenges": CHALLENGE_ID,
                "iam_activation_tokens": ACTIVATION_ID,
                "iam_security_events": IAM_EVENT_ID,
            }.get(table.name, "92345678-1234-4234-8234-123456789012")
        if column.name == "bucket_hash":
            return "b" * 64
        return 1
    name = column.name
    fixed = {
        "username": "synthetic.analyst",
        "username_normalized": "synthetic.analyst",
        "role": "analyst",
        "status": {
            "iam_users": "active", "iam_mfa_factors": "active",
            "security_alerts": "open", "security_correlations": "open",
            "response_records": "simulated",
        }.get(table.name, "active"),
        "password_hash": ARGON_HASH,
        "password_changed_at": NOW,
        "must_change_password": 1,
        "factor_type": "totp",
        "secret_ciphertext": FAKE_CIPHERTEXT,
        "encryption_key_id": "synthetic-key-v1",
        "last_accepted_step": 123456,
        "code_hash": "c" * 64,
        "token_hash": "d" * 64,
        "token_prefix": "aegis-test",
        "scopes_json": '["alerts:read"]',
        "session_hash": "e" * 64,
        "purpose": "login_mfa",
        "challenge_hash": "f" * 64,
        "failed_attempts": 1,
        "success": 1,
        "metadata_json": '{"synthetic":true}',
        "bucket_hash": "b" * 64,
        "scope": "login",
        "failures": 1,
        "version": 1,
        "name": "synthetic_initial_iam_schema",
        "checksum": "9" * 64,
        "event_type": "authentication_failure",
        "source_ip": "198.51.100.23",
        "username": "synthetic.analyst",
        "outcome": "failure",
        "description": "Synthetic rehearsal record",
        "occurred_at": NOW,
        "received_at": NOW,
        "title": "Synthetic suspicious authentication",
        "severity": "high",
        "detection_rule": "AEGIS-AUTH-SYNTHETIC",
        "created_at": NOW,
        "updated_at": NOW,
        "activated_at": NOW,
        "last_login_at": NOW,
        "confirmed_at": NOW,
        "revoked_at": None,
        "used_at": None,
        "expires_at": "2026-11-17T12:00:00+00:00",
        "last_seen_at": NOW,
        "idle_expires_at": "2026-11-16T13:00:00+00:00",
        "absolute_expires_at": "2026-11-17T12:00:00+00:00",
        "mfa_verified_at": NOW,
        "consumed_at": None,
        "source_system": "synthetic-sensor",
        "external_event_id": "synthetic-event-0001",
        "destination_ip": "203.0.113.10",
        "destination_port": 443,
        "protocol": "tcp",
        "author": "synthetic-analyst",
        "content": "Synthetic investigation note",
        "action": "synthetic-investigation-action",
        "summary": "Synthetic incident timeline entry",
        "details": '{"synthetic":true}',
        "actor": "synthetic-analyst",
        "analyst_note": "Synthetic evidence note",
        "linked_by": "synthetic-analyst",
        "linked_at": NOW,
        "previous_value": "open",
        "new_value": "investigating",
        "alert_count": 1,
        "assigned_to": "synthetic-analyst",
        "ip_address": "198.51.100.23",
        "classification": "suspicious",
        "is_global": 1,
        "enrichment_status": "complete",
        "threat_score": 87,
        "confidence": 0.93,
        "reputation": "malicious",
        "categories": '["scanner","bruteforce"]',
        "first_seen": NOW,
        "assessed_at": NOW,
        "provider": "synthetic-provider",
        "error": None,
        "checked_at": NOW,
        "target": "198.51.100.23",
        "mode": "dry_run",
        "requested_by": "synthetic-analyst",
        "policy_allowed": 1,
        "approval_required": 1,
        "executed": 0,
        "simulated": 1,
        "reasons": '["synthetic rehearsal only"]',
        "decided_by": "synthetic-approver",
        "decision_at": NOW,
        "decision_reason": "Synthetic approval decision",
        "event": "response_simulated",
        "previous_hash": None,
        "event_hash": AUDIT_HASH_1,
        "event_count": 2,
        "final_hash": AUDIT_HASH_2,
        "updated_at": NOW,
        "response_id": 1,
        "final_hash": AUDIT_HASH_2,
        "window_started_at": NOW,
        "blocked_until": None,
        "last_used_at": NOW,
        "revocation_reason": None,
    }
    if table.name == "response_audit_log" and name == "event_hash":
        return AUDIT_HASH_1 if parent_rows.get("_audit_index", 1) == 1 else AUDIT_HASH_2
    if table.name == "response_audit_log" and name == "previous_hash":
        return None if parent_rows.get("_audit_index", 1) == 1 else AUDIT_HASH_1
    if name in fixed:
        return fixed[name]
    if column.nullable:
        return None
    if column.server_default is not None:
        return None
    if column.type.python_type is int:
        return 1
    if column.type.python_type is float:
        return 0.5
    if column.type.python_type is bytes:
        return b"synthetic-binary"
    return "synthetic-" + name


def _synthetic_rows():
    tables = list(metadata.sorted_tables)
    ordered_names = dependency_order(tables)
    tables_by_name = {table.name: table for table in tables}
    parent_rows = {}
    rows_by_table = {}
    for name in ordered_names:
        table = tables_by_name[name]
        row = {
            column.name: _value_for_column(table, column, parent_rows)
            for column in table.columns
        }
        # Server defaults are intentionally materialized as explicit values so
        # the digest compares the exact stored row representation.
        if table.name == "response_audit_log":
            first = dict(row)
            first["details"] = json.loads(first["details"])
            first["previous_hash"] = GENESIS_HASH
            first["event_hash"] = calculate_event_hash(first, GENESIS_HASH)

            second = dict(row)
            second["id"] = 2
            second["event"] = "response_chain_continued"
            second["details"] = json.loads(second["details"])
            second["previous_hash"] = first["event_hash"]
            second["event_hash"] = calculate_event_hash(second, second["previous_hash"])

            first["details"] = json.dumps(
                first["details"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
            second["details"] = json.dumps(
                second["details"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
            rows_by_table[name] = [first, second]
            parent_rows[name] = first
        else:
            rows_by_table[name] = [row]
            parent_rows[name] = row
    # Chain-head metadata must describe both synthetic audit events.
    rows_by_table["response_audit_chain_heads"][0]["event_count"] = 2
    rows_by_table["response_audit_chain_heads"][0]["final_hash"] = rows_by_table["response_audit_log"][-1]["event_hash"]
    return tables, rows_by_table


def _insert_synthetic_source(connection, tables, rows_by_table):
    ordered = dependency_order(tables)
    by_name = {table.name: table for table in tables}
    for name in ordered:
        connection.execute(insert(by_name[name]), rows_by_table[name])


@pytest.mark.skipif(
    not os.getenv("AEGIS_TEST_POSTGRES_URL"),
    reason="AEGIS_TEST_POSTGRES_URL is not configured",
)
def test_full_domain_synthetic_transfer_preserves_all_27_tables_and_audit_chain():
    schema = "aegis_full_transfer_test_" + uuid4().hex
    postgres_engine = create_engine(os.environ["AEGIS_TEST_POSTGRES_URL"])
    source_engine = create_engine("sqlite:///:memory:")
    tables, rows_by_table = _synthetic_rows()
    try:
        @event.listens_for(source_engine, "connect")
        def _enable_sqlite_foreign_keys(dbapi_connection, _record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        with postgres_engine.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        metadata.create_all(source_engine)
        metadata.create_all(
            postgres_engine.execution_options(schema_translate_map={None: schema})
        )
        with source_engine.begin() as source:
            _insert_synthetic_source(source, tables, rows_by_table)

        with source_engine.connect() as source:
            with postgres_engine.connect().execution_options(
                schema_translate_map={None: schema}
            ) as destination:
                manifest = transfer_synthetic_tables(
                    source, destination, tables, destination_schema=schema
                )

        assert set(manifest) == {table.name for table in tables}
        assert len(manifest) == 27
        assert all(item["verified"] and item["row_count"] >= 1 for item in manifest.values())
        assert manifest["response_audit_log"]["row_count"] == 2

        with postgres_engine.connect().execution_options(
            schema_translate_map={None: schema}
        ) as destination:
            mfa = destination.execute(
                select(metadata.tables["iam_mfa_factors"])
            ).mappings().one()
            assert bytes(mfa["secret_ciphertext"]) == FAKE_CIPHERTEXT
            assert mfa["encryption_key_id"] == "synthetic-key-v1"
            assert mfa["last_accepted_step"] == 123456

            credential = destination.execute(
                select(metadata.tables["iam_credentials"])
            ).mappings().one()
            assert credential["password_hash"] == ARGON_HASH

            audit_rows = destination.execute(
                select(metadata.tables["response_audit_log"]).order_by(
                    metadata.tables["response_audit_log"].c.id
                )
            ).mappings().all()
            parsed_audit_rows = [
                {**dict(row), "details": json.loads(row["details"])}
                for row in audit_rows
            ]
            audit_verification = verify_hash_chain(parsed_audit_rows)
            assert audit_verification["valid"] is True
            assert audit_verification["event_count"] == 2
            assert audit_rows[0]["previous_hash"] == GENESIS_HASH
            assert audit_rows[1]["previous_hash"] == audit_rows[0]["event_hash"]

            chain_head = destination.execute(
                select(metadata.tables["response_audit_chain_heads"])
            ).mappings().one()
            assert chain_head["event_count"] == 2
            assert chain_head["final_hash"] == audit_rows[-1]["event_hash"]

            # Verify the explicit primary-key import did not leave sequences
            # behind the imported values in the target PostgreSQL schema.
            next_alert_id = destination.execute(
                insert(metadata.tables["security_alerts"])
                .values(
                    title="Sequence probe", severity="low",
                    description="Synthetic sequence check",
                    detection_rule="SEQUENCE-PROBE", created_at=NOW,
                )
                .returning(metadata.tables["security_alerts"].c.id)
            ).scalar_one()
            assert next_alert_id > 1
    finally:
        with postgres_engine.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        source_engine.dispose()
        postgres_engine.dispose()
