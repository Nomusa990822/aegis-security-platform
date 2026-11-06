
from app.database import get_connection


def initialize_idempotency_schema():
    """
    Add source identifiers to security events.

    The migration is safe to run repeatedly and preserves
    existing security event records.
    """
    with get_connection() as connection:
        existing_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(security_events)"
            ).fetchall()
        }

        migrations = {
            "source_system": "TEXT",
            "external_event_id": "TEXT",
        }

        for column_name, column_type in migrations.items():
            if column_name not in existing_columns:
                connection.execute(
                    f"""
                    ALTER TABLE security_events
                    ADD COLUMN {column_name} {column_type}
                    """
                )

        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS
                idx_security_events_external_identity
            ON security_events (
                source_system,
                external_event_id
            )
            WHERE external_event_id IS NOT NULL
            """
        )

        connection.commit()
