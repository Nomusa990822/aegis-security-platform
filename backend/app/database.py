import sqlite3
from pathlib import Path

DATABASE_PATH = Path(__file__).resolve().parent.parent / "aegis.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON;")
    return connection


def initialize_database():
    with get_connection() as connection:

        # --------------------------------------------------
        # SECURITY EVENT STORAGE
        # --------------------------------------------------

        connection.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                source_ip TEXT,
                username TEXT,
                outcome TEXT,
                description TEXT,
                occurred_at TEXT NOT NULL,
                received_at TEXT NOT NULL
            )
        """)

        # --------------------------------------------------
        # SECURITY ALERT STORAGE
        # --------------------------------------------------

        connection.execute("""
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                source_ip TEXT,
                detection_rule TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT DEFAULT 'open'
            )
        """)

        # --------------------------------------------------
        # SAFE EVENT TABLE MIGRATIONS
        # --------------------------------------------------

        existing_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(security_events)"
            ).fetchall()
        }

        network_columns = {
            "destination_ip": "TEXT",
            "destination_port": "INTEGER",
            "protocol": "TEXT"
        }

        for column_name, column_type in network_columns.items():
            if column_name not in existing_columns:
                connection.execute(
                    f"ALTER TABLE security_events "
                    f"ADD COLUMN {column_name} {column_type}"
                )

        # --------------------------------------------------
        # INDIVIDUAL ALERT INVESTIGATION
        # --------------------------------------------------

        connection.execute("""
            CREATE TABLE IF NOT EXISTS incident_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                author TEXT NOT NULL DEFAULT 'analyst',
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (alert_id)
                    REFERENCES security_alerts(id)
                    ON DELETE CASCADE
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS incident_timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                summary TEXT NOT NULL,
                details TEXT,
                actor TEXT NOT NULL DEFAULT 'analyst',
                created_at TEXT NOT NULL,
                FOREIGN KEY (alert_id)
                    REFERENCES security_alerts(id)
                    ON DELETE CASCADE
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS incident_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                event_id INTEGER NOT NULL,
                analyst_note TEXT,
                linked_by TEXT NOT NULL DEFAULT 'analyst',
                linked_at TEXT NOT NULL,
                UNIQUE (alert_id, event_id),
                FOREIGN KEY (alert_id)
                    REFERENCES security_alerts(id)
                    ON DELETE CASCADE,
                FOREIGN KEY (event_id)
                    REFERENCES security_events(id)
                    ON DELETE CASCADE
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS alert_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL DEFAULT 'analyst',
                previous_value TEXT,
                new_value TEXT,
                details TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (alert_id)
                    REFERENCES security_alerts(id)
                    ON DELETE CASCADE
            )
        """)

        # --------------------------------------------------
        # ALERT INVESTIGATION INDEXES
        # --------------------------------------------------

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_incident_notes_alert
            ON incident_notes(alert_id)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_incident_timeline_alert
            ON incident_timeline(alert_id)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_incident_evidence_alert
            ON incident_evidence(alert_id)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_alert_audit_log_alert
            ON alert_audit_log(alert_id)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_network_event_correlation
            ON security_events(
                event_type,
                source_ip,
                destination_ip,
                received_at
            )
        """)

        # --------------------------------------------------
        # SECURITY CORRELATION CASES
        # --------------------------------------------------

        connection.execute("""
            CREATE TABLE IF NOT EXISTS security_correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                description TEXT NOT NULL,
                alert_count INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                assigned_to TEXT
            )
        """)

        # Safely migrate existing correlation tables.
        correlation_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(security_correlations)"
            ).fetchall()
        }

        if "assigned_to" not in correlation_columns:
            connection.execute("""
                ALTER TABLE security_correlations
                ADD COLUMN assigned_to TEXT
            """)

        # --------------------------------------------------
        # ALERT-TO-CORRELATION RELATIONSHIPS
        # --------------------------------------------------

        connection.execute("""
            CREATE TABLE IF NOT EXISTS security_correlation_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                correlation_id INTEGER NOT NULL,
                alert_id INTEGER NOT NULL,
                linked_at TEXT NOT NULL,
                UNIQUE (correlation_id, alert_id),
                FOREIGN KEY (correlation_id)
                    REFERENCES security_correlations(id)
                    ON DELETE CASCADE,
                FOREIGN KEY (alert_id)
                    REFERENCES security_alerts(id)
                    ON DELETE CASCADE
            )
        """)

        # --------------------------------------------------
        # CORRELATION INVESTIGATION NOTES
        # --------------------------------------------------

        connection.execute("""
            CREATE TABLE IF NOT EXISTS correlation_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                correlation_id INTEGER NOT NULL,
                author TEXT NOT NULL DEFAULT 'analyst',
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (correlation_id)
                    REFERENCES security_correlations(id)
                    ON DELETE CASCADE
            )
        """)

        # --------------------------------------------------
        # CORRELATION CASE TIMELINE
        # --------------------------------------------------

        connection.execute("""
            CREATE TABLE IF NOT EXISTS correlation_timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                correlation_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                summary TEXT NOT NULL,
                details TEXT,
                actor TEXT NOT NULL DEFAULT 'analyst',
                created_at TEXT NOT NULL,
                FOREIGN KEY (correlation_id)
                    REFERENCES security_correlations(id)
                    ON DELETE CASCADE
            )
        """)

        # --------------------------------------------------
        # CORRELATION CASE AUDIT HISTORY
        # --------------------------------------------------

        connection.execute("""
            CREATE TABLE IF NOT EXISTS correlation_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                correlation_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL DEFAULT 'analyst',
                previous_value TEXT,
                new_value TEXT,
                details TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (correlation_id)
                    REFERENCES security_correlations(id)
                    ON DELETE CASCADE
            )
        """)

        # --------------------------------------------------
        # CORRELATION INDEXES
        # --------------------------------------------------

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_correlations_source_ip
            ON security_correlations(source_ip)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_correlation_alerts_correlation
            ON security_correlation_alerts(correlation_id)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_correlation_alerts_alert
            ON security_correlation_alerts(alert_id)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_correlation_notes_case
            ON correlation_notes(correlation_id)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_correlation_timeline_case
            ON correlation_timeline(correlation_id)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_correlation_audit_case
            ON correlation_audit_log(correlation_id)
        """)

        # ----------------------------------------------------------------------
        # THREAT INTELLIGENCE ASSESSMENTS
        # ----------------------------------------------------------------------

        connection.execute("""
            CREATE TABLE IF NOT EXISTS ip_intelligence_assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                classification TEXT NOT NULL,
                is_global INTEGER NOT NULL,
                enrichment_status TEXT NOT NULL,
                threat_score INTEGER NOT NULL DEFAULT 0,
                confidence REAL NOT NULL DEFAULT 0.0,
                reputation TEXT NOT NULL DEFAULT 'unknown',
                categories TEXT NOT NULL DEFAULT '[]',
                first_seen TEXT,
                last_seen TEXT,
                assessed_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (alert_id)
                    REFERENCES security_alerts(id)
                    ON DELETE SET NULL
            )
        """)

        # ----------------------------------------------------------------------
        # ASSESSMENT TO ALERT RELATIONSHIP
        # ----------------------------------------------------------------------

        # Add alert_id separately so assessments can exist independently
        # and later be associated with one or more security alerts.
        assessment_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(ip_intelligence_assessments)"
            ).fetchall()
        }

        if "alert_id" not in assessment_columns:
            connection.execute("""
                ALTER TABLE ip_intelligence_assessments
                ADD COLUMN alert_id INTEGER
                REFERENCES security_alerts(id)
                ON DELETE SET NULL
            """)

        # ----------------------------------------------------------------------
        # INDIVIDUAL INTELLIGENCE PROVIDER RESULTS
        # ----------------------------------------------------------------------

        connection.execute("""
            CREATE TABLE IF NOT EXISTS ip_intelligence_provider_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id INTEGER NOT NULL,
                provider TEXT NOT NULL,
                status TEXT NOT NULL,
                reputation TEXT,
                confidence REAL NOT NULL DEFAULT 0.0,
                categories TEXT NOT NULL DEFAULT '[]',
                details TEXT NOT NULL DEFAULT '{}',
                error TEXT,
                checked_at TEXT NOT NULL,
                FOREIGN KEY (assessment_id)
                    REFERENCES ip_intelligence_assessments(id)
                    ON DELETE CASCADE
            )
        """)

        # ----------------------------------------------------------------------
        # THREAT INTELLIGENCE INDEXES
        # ----------------------------------------------------------------------

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_intelligence_assessments_ip
            ON ip_intelligence_assessments(ip_address)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_intelligence_assessments_alert
            ON ip_intelligence_assessments(alert_id)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_intelligence_assessments_time
            ON ip_intelligence_assessments(assessed_at)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_intelligence_provider_assessment
            ON ip_intelligence_provider_results(assessment_id)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_intelligence_provider_name
            ON ip_intelligence_provider_results(provider)
        """)

        # --------------------------------------------------
        # SEED EXISTING ALERT TIMELINES
        # --------------------------------------------------

        connection.execute("""
            INSERT INTO incident_timeline (
                alert_id,
                action,
                summary,
                details,
                actor,
                created_at
            )
            SELECT
                a.id,
                'alert_created',
                'Security alert generated: ' || a.title,
                a.description,
                'system',
                a.created_at
            FROM security_alerts AS a
            WHERE NOT EXISTS (
                SELECT 1
                FROM incident_timeline AS t
                WHERE t.alert_id = a.id
            )
        """)

        # --------------------------------------------------
        # SEED EXISTING CORRELATION CASE TIMELINES
        # --------------------------------------------------

        connection.execute("""
            INSERT INTO correlation_timeline (
                correlation_id,
                action,
                summary,
                details,
                actor,
                created_at
            )
            SELECT
                c.id,
                'correlation_created',
                'Correlation case created: ' || c.title,
                c.description,
                'system',
                c.created_at
            FROM security_correlations AS c
            WHERE NOT EXISTS (
                SELECT 1
                FROM correlation_timeline AS t
                WHERE t.correlation_id = c.id
            )
        """)

        connection.commit()
