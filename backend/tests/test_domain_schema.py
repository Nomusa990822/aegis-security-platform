"""Cross-domain schema contract tests for the PostgreSQL migration model."""
from sqlalchemy import create_engine, inspect

from app.db_schema import metadata


EXPECTED_TABLES = {
    "security_events", "security_alerts", "incident_notes", "incident_timeline",
    "incident_evidence", "alert_audit_log", "security_correlations",
    "security_correlation_alerts", "correlation_notes", "correlation_timeline",
    "correlation_audit_log", "ip_intelligence_assessments",
    "ip_intelligence_provider_results", "iam_users", "iam_credentials",
    "iam_mfa_factors", "iam_recovery_codes", "iam_access_tokens", "iam_sessions",
    "iam_auth_challenges", "iam_activation_tokens", "iam_security_events",
    "iam_auth_rate_limits", "iam_schema_migrations", "response_records",
    "response_audit_log", "response_audit_chain_heads",
}


def test_complete_domain_schema_creates_on_sqlite():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    try:
        metadata.create_all(engine)
        assert set(inspect(engine).get_table_names()) == EXPECTED_TABLES
    finally:
        engine.dispose()


def test_operational_foreign_keys_preserve_cascade_semantics():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    try:
        metadata.create_all(engine)
        inspector = inspect(engine)
        evidence_fks = inspector.get_foreign_keys("incident_evidence")
        assert {
            (fk["referred_table"], fk["options"].get("ondelete"))
            for fk in evidence_fks
        } == {("security_alerts", "CASCADE"), ("security_events", "CASCADE")}

        intelligence_fk = inspector.get_foreign_keys("ip_intelligence_assessments")
        assert any(
            fk["referred_table"] == "security_alerts"
            and fk["options"].get("ondelete") == "SET NULL"
            for fk in intelligence_fk
        )
    finally:
        engine.dispose()


def test_iam_and_audit_storage_types_remain_compatible():
    assert str(metadata.tables["iam_mfa_factors"].c.secret_ciphertext.type) == "BLOB"
    assert str(metadata.tables["ip_intelligence_assessments"].c.is_global.type) == "INTEGER"
    assert str(metadata.tables["ip_intelligence_assessments"].c.categories.type) == "TEXT"
    assert str(metadata.tables["response_audit_log"].c.event_hash.type) == "TEXT"
    assert str(metadata.tables["response_audit_chain_heads"].c.final_hash.type) == "TEXT"
