"""Threat-intelligence persistence schema; JSON documents remain serialized TEXT."""
from sqlalchemy import Column, Float, ForeignKey, Index, Integer, Table, Text
from app.db_schema import metadata

ip_intelligence_assessments = Table(
    "ip_intelligence_assessments", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("ip_address", Text, nullable=False), Column("classification", Text, nullable=False),
    Column("is_global", Integer, nullable=False), Column("enrichment_status", Text, nullable=False),
    Column("threat_score", Integer, nullable=False, server_default="0"),
    Column("confidence", Float, nullable=False, server_default="0.0"),
    Column("reputation", Text, nullable=False, server_default="unknown"),
    Column("categories", Text, nullable=False, server_default="[]"),
    Column("first_seen", Text), Column("last_seen", Text),
    Column("assessed_at", Text, nullable=False), Column("created_at", Text, nullable=False),
    Column("alert_id", Integer, ForeignKey("security_alerts.id", ondelete="SET NULL")),
    Index("idx_intelligence_assessments_ip", "ip_address"),
    Index("idx_intelligence_assessments_alert", "alert_id"),
    Index("idx_intelligence_assessments_time", "assessed_at"),
)

ip_intelligence_provider_results = Table(
    "ip_intelligence_provider_results", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("assessment_id", Integer, ForeignKey("ip_intelligence_assessments.id", ondelete="CASCADE"), nullable=False),
    Column("provider", Text, nullable=False), Column("status", Text, nullable=False),
    Column("reputation", Text), Column("confidence", Float, nullable=False, server_default="0.0"),
    Column("categories", Text, nullable=False, server_default="[]"),
    Column("details", Text, nullable=False, server_default="{}"),
    Column("error", Text), Column("checked_at", Text, nullable=False),
    Index("idx_intelligence_provider_assessment", "assessment_id"),
    Index("idx_intelligence_provider_name", "provider"),
)
