"""Operational event, alert, investigation and correlation schema."""
from sqlalchemy import Column, ForeignKey, Index, Integer, Table, Text, UniqueConstraint, text
from app.db_schema import metadata

security_events = Table("security_events", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("event_type", Text, nullable=False), Column("source_ip", Text),
    Column("username", Text), Column("outcome", Text), Column("description", Text),
    Column("occurred_at", Text, nullable=False), Column("received_at", Text, nullable=False),
    Column("destination_ip", Text), Column("destination_port", Integer), Column("protocol", Text),
    Column("source_system", Text), Column("external_event_id", Text),
    Index("idx_network_event_correlation", "event_type", "source_ip", "destination_ip", "received_at"),
    Index("idx_security_events_external_identity", "source_system", "external_event_id",
          unique=True, sqlite_where=text("external_event_id IS NOT NULL"),
          postgresql_where=__import__("sqlalchemy").text("external_event_id IS NOT NULL")))

security_alerts = Table("security_alerts", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True), Column("title", Text, nullable=False),
    Column("severity", Text, nullable=False), Column("description", Text, nullable=False),
    Column("source_ip", Text), Column("detection_rule", Text, nullable=False),
    Column("created_at", Text, nullable=False), Column("status", Text, server_default="open"))

incident_notes = Table("incident_notes", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("alert_id", Integer, ForeignKey("security_alerts.id", ondelete="CASCADE"), nullable=False),
    Column("author", Text, nullable=False, server_default="analyst"),
    Column("content", Text, nullable=False), Column("created_at", Text, nullable=False),
    Index("idx_incident_notes_alert", "alert_id"))

incident_timeline = Table("incident_timeline", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("alert_id", Integer, ForeignKey("security_alerts.id", ondelete="CASCADE"), nullable=False),
    Column("action", Text, nullable=False), Column("summary", Text, nullable=False),
    Column("details", Text), Column("actor", Text, nullable=False, server_default="analyst"),
    Column("created_at", Text, nullable=False), Index("idx_incident_timeline_alert", "alert_id"))

incident_evidence = Table("incident_evidence", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("alert_id", Integer, ForeignKey("security_alerts.id", ondelete="CASCADE"), nullable=False),
    Column("event_id", Integer, ForeignKey("security_events.id", ondelete="CASCADE"), nullable=False),
    Column("analyst_note", Text), Column("linked_by", Text, nullable=False, server_default="analyst"),
    Column("linked_at", Text, nullable=False),
    UniqueConstraint("alert_id", "event_id", name="uq_incident_evidence_alert_event"),
    Index("idx_incident_evidence_alert", "alert_id"))

alert_audit_log = Table("alert_audit_log", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("alert_id", Integer, ForeignKey("security_alerts.id", ondelete="CASCADE"), nullable=False),
    Column("action", Text, nullable=False), Column("actor", Text, nullable=False, server_default="analyst"),
    Column("previous_value", Text), Column("new_value", Text), Column("details", Text),
    Column("created_at", Text, nullable=False), Index("idx_alert_audit_log_alert", "alert_id"))

security_correlations = Table("security_correlations", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True), Column("title", Text, nullable=False),
    Column("severity", Text, nullable=False), Column("source_ip", Text),
    Column("description", Text, nullable=False), Column("alert_count", Integer, nullable=False, server_default="0"),
    Column("status", Text, nullable=False, server_default="open"), Column("created_at", Text, nullable=False),
    Column("updated_at", Text, nullable=False), Column("assigned_to", Text), Index("idx_correlations_source_ip", "source_ip"))

security_correlation_alerts = Table("security_correlation_alerts", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("correlation_id", Integer, ForeignKey("security_correlations.id", ondelete="CASCADE", name="fk_corr_alerts_correlation"), nullable=False),
    Column("alert_id", Integer, ForeignKey("security_alerts.id", ondelete="CASCADE", name="fk_corr_alerts_alert"), nullable=False),
    Column("linked_at", Text, nullable=False),
    UniqueConstraint("correlation_id", "alert_id", name="uq_security_correlation_alerts_pair"),
    Index("idx_correlation_alerts_correlation", "correlation_id"),
    Index("idx_correlation_alerts_alert", "alert_id"))

correlation_notes = Table("correlation_notes", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("correlation_id", Integer, ForeignKey("security_correlations.id", ondelete="CASCADE"), nullable=False),
    Column("author", Text, nullable=False, server_default="analyst"), Column("content", Text, nullable=False),
    Column("created_at", Text, nullable=False))

correlation_timeline = Table("correlation_timeline", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("correlation_id", Integer, ForeignKey("security_correlations.id", ondelete="CASCADE"), nullable=False),
    Column("action", Text, nullable=False), Column("summary", Text, nullable=False), Column("details", Text),
    Column("actor", Text, nullable=False, server_default="analyst"), Column("created_at", Text, nullable=False))

correlation_audit_log = Table("correlation_audit_log", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("correlation_id", Integer, ForeignKey("security_correlations.id", ondelete="CASCADE"), nullable=False),
    Column("action", Text, nullable=False), Column("actor", Text, nullable=False, server_default="analyst"),
    Column("previous_value", Text), Column("new_value", Text), Column("details", Text),
    Column("created_at", Text, nullable=False))
