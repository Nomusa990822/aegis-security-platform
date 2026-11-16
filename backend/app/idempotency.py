
from app.database import get_connection, _postgres_url


def initialize_idempotency_schema():
    # The PostgreSQL idempotency columns and partial unique index are owned
    # by the reviewed Alembic baseline; never issue SQLite PRAGMA/DDL here.
    if _postgres_url():
        with get_connection() as connection:
            columns = connection.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = current_schema() "
                "AND table_name = 'security_events'"
            ).fetchall()
            names = {row["column_name"] for row in columns}
            if not {"source_system", "external_event_id"}.issubset(names):
                raise RuntimeError("PostgreSQL event idempotency schema is incomplete")
        return
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
