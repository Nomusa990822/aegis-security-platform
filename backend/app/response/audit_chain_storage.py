
import json

from app.response.audit_chain import (
    GENESIS_HASH,
    calculate_event_hash,
)
from app.response.audit_checkpoint import reject_duplicate_json_keys


def initialize_audit_chain_storage(connection):
    """Create hash-chain storage and backfill existing audit events."""

    columns = {
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(response_audit_log)"
        ).fetchall()
    }

    if "previous_hash" not in columns:
        connection.execute("""
            ALTER TABLE response_audit_log
            ADD COLUMN previous_hash TEXT
        """)

    if "event_hash" not in columns:
        connection.execute("""
            ALTER TABLE response_audit_log
            ADD COLUMN event_hash TEXT
        """)

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

    response_rows = connection.execute("""
        SELECT DISTINCT response_id
        FROM response_audit_log
        ORDER BY response_id ASC
    """).fetchall()

    for response_row in response_rows:
        response_id = response_row["response_id"]

        events = connection.execute("""
            SELECT *
            FROM response_audit_log
            WHERE response_id = ?
            ORDER BY id ASC
        """, (response_id,)).fetchall()

        previous_hash = GENESIS_HASH
        event_count = 0

        for row in events:
            event = dict(row)

            try:
                details = json.loads(
                    event["details"],
                    object_pairs_hook=reject_duplicate_json_keys,
                )
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
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

                connection.execute("""
                    UPDATE response_audit_log
                    SET previous_hash = ?,
                        event_hash = ?
                    WHERE id = ?
                """, (
                    previous_hash,
                    event_hash,
                    event["id"],
                ))

                previous_hash = event_hash

            event_count += 1

        if event_count:
            connection.execute("""
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
            """, (
                response_id,
                event_count,
                previous_hash,
            ))


def append_audit_event(
    connection,
    response_id: int,
    alert_id: int,
    event: str,
    actor: str,
    details: dict,
    created_at: str,
) -> int:
    """
    Append one cryptographically linked audit event.

    The caller owns the transaction. This function never commits.
    """

    if not isinstance(details, dict):
        raise ValueError("Audit event details must be a dictionary.")

    head = connection.execute("""
        SELECT event_count, final_hash
        FROM response_audit_chain_heads
        WHERE response_id = ?
    """, (response_id,)).fetchone()

    if head is None:
        existing = connection.execute("""
            SELECT COUNT(*) AS event_count
            FROM response_audit_log
            WHERE response_id = ?
        """, (response_id,)).fetchone()

        if existing["event_count"] > 0:
            raise ValueError(
                "Existing audit events have no chain head. "
                "Run the audit-chain migration before appending."
            )

        previous_hash = GENESIS_HASH
        event_count = 0
    else:
        previous_hash = head["final_hash"]
        event_count = head["event_count"]

    details_json = json.dumps(
        details,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    cursor = connection.execute("""
        INSERT INTO response_audit_log (
            response_id,
            alert_id,
            event,
            actor,
            details,
            created_at,
            previous_hash,
            event_hash
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
    """, (
        response_id,
        alert_id,
        event,
        actor,
        details_json,
        created_at,
        previous_hash,
    ))

    event_id = cursor.lastrowid

    event_payload = {
        "id": event_id,
        "response_id": response_id,
        "alert_id": alert_id,
        "event": event,
        "actor": actor,
        "details": details,
        "created_at": created_at,
        "previous_hash": previous_hash,
    }

    event_hash = calculate_event_hash(
        event_payload,
        previous_hash,
    )

    connection.execute("""
        UPDATE response_audit_log
        SET event_hash = ?
        WHERE id = ?
    """, (event_hash, event_id))

    connection.execute("""
        INSERT INTO response_audit_chain_heads (
            response_id,
            event_count,
            final_hash,
            updated_at
        )
        VALUES (?, ?, ?, ?)
        ON CONFLICT(response_id)
        DO UPDATE SET
            event_count = excluded.event_count,
            final_hash = excluded.final_hash,
            updated_at = excluded.updated_at
    """, (
        response_id,
        event_count + 1,
        event_hash,
        created_at,
    ))

    return event_id
