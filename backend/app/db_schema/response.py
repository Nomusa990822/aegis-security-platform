"""Response and tamper-evident audit database schema."""
from sqlalchemy import Column, ForeignKey, Index, Integer, Table, Text
from app.db_schema import metadata

response_records = Table("response_records", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("alert_id", Integer, ForeignKey("security_alerts.id", ondelete="CASCADE"), nullable=False),
    Column("action", Text, nullable=False), Column("target", Text, nullable=False), Column("mode", Text, nullable=False),
    Column("requested_by", Text, nullable=False), Column("status", Text, nullable=False),
    Column("policy_allowed", Integer, nullable=False), Column("approval_required", Integer, nullable=False),
    Column("executed", Integer, nullable=False), Column("simulated", Integer, nullable=False),
    Column("reasons", Text, nullable=False), Column("created_at", Text, nullable=False),
    Column("decided_by", Text), Column("decision_at", Text), Column("decision_reason", Text),
    Index("idx_response_records_alert", "alert_id"), Index("idx_response_records_created", "created_at"))

response_audit_log = Table("response_audit_log", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("response_id", Integer, ForeignKey("response_records.id", ondelete="CASCADE"), nullable=False),
    Column("alert_id", Integer, ForeignKey("security_alerts.id", ondelete="CASCADE"), nullable=False),
    Column("event", Text, nullable=False), Column("actor", Text, nullable=False),
    Column("details", Text, nullable=False), Column("created_at", Text, nullable=False),
    Column("previous_hash", Text), Column("event_hash", Text),
    Index("idx_response_audit_response", "response_id"))

response_audit_chain_heads = Table("response_audit_chain_heads", metadata,
    Column("response_id", Integer, ForeignKey("response_records.id", ondelete="CASCADE"), primary_key=True),
    Column("event_count", Integer, nullable=False), Column("final_hash", Text, nullable=False),
    Column("updated_at", Text, nullable=False))
