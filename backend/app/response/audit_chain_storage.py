
import json

from app.response.audit_chain import (
    GENESIS_HASH,
    calculate_event_hash,
)


def initialize_audit_chain_storage(connection):
    """Create hash-chain storage and backfill existing audit events."""

    columns = {
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(response_audit_log)"
        ).fetchall()
    }

    if "previous_hash" not in columns:
        connection.execute(
            """
            ALTER TABLE response_audit_log
            ADD COLUMN previous_hash TEXT
            """
        )

    if "event_hash" not in columns:
        connection.execute(
            """
            ALTER TABLE response_audit_log
            ADD COLUMN event_hash TEXT
            """
        )

    connection.execute("""
        CREATE TABLE IF NOT EXISTS response_audit_chain_heads (
            response_id INTEGER PRIMARY KEY,
            event_count INTEGER NOT NULL,
            final_hash TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (response_id)
                REFERENCES response_records(id)
                ON DELETE CASCADE
        )
    """)

    response_rows = connection.execute(
        """
        SELECT DISTINCT response_id
        FROM response_audit_log
        ORDER BY response_id ASC
        """
    ).fetchall()

    for response_row in response_rows:
        response_id = response_row["response_id"]

        events = connection.execute(
            """
            SELECT *
            FROM response_audit_log
            WHERE response_id = ?
            ORDER BY id ASC
            """,
            (response_id,),
        ).fetchall()

        previous_hash = GENESIS_HASH
        event_count = 0

        for row in events:
            event = dict(row)

            try:
                details = json.loads(event["details"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise ValueError(
                    f"Cannot backfill audit event {event['id']}: "
                    "details contain invalid JSON."
                ) from exc

            if not isinstance(details, dict):
                raise ValueError(
                    f"Cannot backfill audit event {event['id']}: "
                    "details must contain a JSON object."
                )

            event["details"] = details

            stored_previous_hash = event.get("previous_hash")
            stored_event_hash = event.get("event_hash")

            if stored_previous_hash and stored_event_hash:
                if stored_previous_hash != previous_hash:
                    raise ValueError(
                        f"Existing hash chain is inconsistent at "
                        f"audit event {event['id']}."
                    )

                expected_hash = calculate_event_hash(
                    event,
                    previous_hash,
                )

                if stored_event_hash != expected_hash:
                    raise ValueError(
                        f"Existing event hash is invalid at "
                        f"audit event {event['id']}."
                    )

                previous_hash = stored_event_hash

            else:
                event_hash = calculate_event_hash(
                    event,
                    previous_hash,
                )

                connection.execute(
                    """
                    UPDATE response_audit_log
                    SET previous_hash = ?,
                        event_hash = ?
                    WHERE id = ?
                    """,
                    (
                        previous_hash,
                        event_hash,
                        event["id"],
                    ),
                )

                previous_hash = event_hash

            event_count += 1

        if event_count:
            connection.execute(
                """
                INSERT INTO response_audit_chain_heads (
                    response_id,
                    event_count,
                    final_hash,
                    updated_at
                )
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(response_id)
                DO UPDATE SET
                    event_count = excluded.event_count,
                    final_hash = excluded.final_hash,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    response_id,
                    event_count,
                    previous_hash,
                ),
            )
