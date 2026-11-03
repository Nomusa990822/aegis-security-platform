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

        # Security event storage.
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

        # Security alert storage.
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

        # Safely migrate existing event tables.
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

        # Analyst investigation notes.
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

        # Chronological incident activity.
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

        # Security events associated with an incident.
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

        # Audit trail for alert management actions.
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

        # Investigation indexes.
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

        # Network detection query index.
        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_network_event_correlation
            ON security_events(
                event_type,
                source_ip,
                destination_ip,
                received_at
            )
        """)

        # Seed timeline entries for pre-existing alerts.
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

        connection.commit()
