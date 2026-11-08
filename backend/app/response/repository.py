
import json
import logging
from datetime import datetime, timezone

from app.response.models import ResponseRequest, ResponseResult
from app.response.audit import validate_response_audit
from app.response.audit_chain import GENESIS_HASH, verify_hash_chain
from app.response.audit_chain_storage import (
    append_audit_event,
    initialize_audit_chain_storage,
)
from app.response.audit_checkpoint import (
    verify_audit_checkpoint,
    write_audit_checkpoint,
)


def initialize_response_tables(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS response_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            mode TEXT NOT NULL,
            requested_by TEXT NOT NULL,
            status TEXT NOT NULL,
            policy_allowed INTEGER NOT NULL,
            approval_required INTEGER NOT NULL,
            executed INTEGER NOT NULL,
            simulated INTEGER NOT NULL,
            reasons TEXT NOT NULL,
            created_at TEXT NOT NULL,
            decided_by TEXT,
            decision_at TEXT,
            decision_reason TEXT,
            FOREIGN KEY (alert_id)
                REFERENCES security_alerts(id)
                ON DELETE CASCADE
        )
    """)

    existing_columns = {
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(response_records)"
        ).fetchall()
    }

    decision_columns = {
        "decided_by": "TEXT",
        "decision_at": "TEXT",
        "decision_reason": "TEXT",
    }

    for column_name, column_type in decision_columns.items():
        if column_name not in existing_columns:
            connection.execute(
                f"ALTER TABLE response_records "
                f"ADD COLUMN {column_name} {column_type}"
            )

    connection.execute("""
        CREATE TABLE IF NOT EXISTS response_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            response_id INTEGER NOT NULL,
            alert_id INTEGER NOT NULL,
            event TEXT NOT NULL,
            actor TEXT NOT NULL,
            details TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (response_id)
                REFERENCES response_records(id)
                ON DELETE CASCADE,
            FOREIGN KEY (alert_id)
                REFERENCES security_alerts(id)
                ON DELETE CASCADE
        )
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_response_records_alert
        ON response_records(alert_id)
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_response_records_created
        ON response_records(created_at)
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_response_audit_response
        ON response_audit_log(response_id)
    """)

    initialize_audit_chain_storage(connection)


def _write_committed_audit_checkpoint(connection, response_id: int):
    """
    Protect the committed audit-chain head with an external signed checkpoint.

    The database transaction must already be committed before this runs.

    Before advancing the checkpoint, verify the previous checkpoint.
    A missing or invalid checkpoint must never be silently recreated
    or overwritten.

    Checkpoint failure is logged; it must not make a committed operation
    appear to have rolled back.
    """
    try:
        head = connection.execute(
            """
            SELECT event_count, final_hash
            FROM response_audit_chain_heads
            WHERE response_id = ?
            """,
            (response_id,),
        ).fetchone()

        if head is None:
            raise RuntimeError(
                "Cannot checkpoint a response without an audit-chain head."
            )

        event_count = head["event_count"]
        previous_event_count = event_count - 1

        if previous_event_count < 0:
            raise RuntimeError(
                "Invalid audit-chain event count."
            )

        if previous_event_count == 0:
            previous_final_hash = GENESIS_HASH

        else:
            previous_event = connection.execute(
                """
                SELECT event_hash
                FROM response_audit_log
                WHERE response_id = ?
                ORDER BY id DESC
                LIMIT 1 OFFSET 1
                """,
                (response_id,),
            ).fetchone()

            if previous_event is None:
                raise RuntimeError(
                    "Cannot locate the previous audit-chain event."
                )

            previous_final_hash = previous_event["event_hash"]

            if not previous_final_hash:
                raise RuntimeError(
                    "Previous audit-chain event has no hash."
                )

        write_audit_checkpoint(
            response_id=response_id,
            event_count=event_count,
            final_hash=head["final_hash"],
            previous_event_count=previous_event_count,
            previous_final_hash=previous_final_hash,
        )

        return True

    except Exception:
        logging.exception(
            "Failed to write external audit checkpoint for response %s.",
            response_id,
        )
        return False



def verify_response_audit_before_mutation(connection, response_id: int):
    """
    Verify all existing response evidence before a lifecycle mutation.

    The caller must hold a write transaction (BEGIN IMMEDIATE) so another
    SQLite writer cannot change the response or its audit chain mid-check.
    """
    errors = []

    try:
        record = get_response_record(connection, response_id)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        return {
            "valid": False,
            "errors": [f"Response record could not be read: {exc}"],
        }

    if record is None:
        return {
            "valid": False,
            "errors": ["Response record does not exist."],
        }

    lifecycle = validate_response_audit(record)
    if not lifecycle["valid"]:
        errors.extend(
            f"Lifecycle validation: {error}"
            for error in lifecycle["errors"]
        )

    chain_result = verify_hash_chain(record["audit_log"])
    if not chain_result["valid"]:
        errors.extend(
            f"Hash-chain validation: {error}"
            for error in chain_result["errors"]
        )

    head = connection.execute(
        """
        SELECT event_count, final_hash
        FROM response_audit_chain_heads
        WHERE response_id = ?
        """,
        (response_id,),
    ).fetchone()

    if head is None:
        errors.append("Database audit-chain head is missing.")
        return {"valid": False, "errors": errors}

    if head["event_count"] != chain_result["event_count"]:
        errors.append(
            "Database audit-chain head event count does not match "
            "the verified audit events."
        )

    if head["final_hash"] != chain_result["final_hash"]:
        errors.append(
            "Database audit-chain head final hash does not match "
            "the verified audit events."
        )

    if chain_result["valid"] and not errors:
        checkpoint = verify_audit_checkpoint(
            response_id=response_id,
            event_count=head["event_count"],
            final_hash=head["final_hash"],
        )
        if not checkpoint["valid"]:
            errors.extend(
                f"Signed checkpoint validation: {error}"
                for error in checkpoint["errors"]
            )

    return {
        "valid": not errors,
        "errors": errors,
    }

def save_response(
    connection,
    request: ResponseRequest,
    result: ResponseResult,
) -> int:
    created_at = datetime.now(timezone.utc).isoformat()

    cursor = connection.execute(
        """
        INSERT INTO response_records (
            alert_id,
            action,
            target,
            mode,
            requested_by,
            status,
            policy_allowed,
            approval_required,
            executed,
            simulated,
            reasons,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            request.alert_id,
            request.action.value,
            request.target,
            request.mode.value,
            request.requested_by,
            result.status.value,
            int(result.policy_allowed),
            int(result.approval_required),
            int(result.executed),
            int(result.simulated),
            json.dumps(list(result.reasons)),
            created_at,
        ),
    )

    response_id = cursor.lastrowid

    append_audit_event(
        connection=connection,
        response_id=response_id,
        alert_id=request.alert_id,
        event="response_request_created",
        actor=request.requested_by,
        details={
            "status": result.status.value,
            "action": request.action.value,
            "target": request.target,
            "policy_allowed": result.policy_allowed,
            "approval_required": result.approval_required,
            "executed": result.executed,
            "simulated": result.simulated,
        },
        created_at=created_at,
    )

    connection.commit()

    _write_committed_audit_checkpoint(
        connection,
        response_id,
    )

    return response_id


def decide_response(
    connection,
    response_id: int,
    actor_id: str,
    decision: str,
    reason: str = "",
) -> str:
    if decision not in {"approved", "rejected"}:
        raise ValueError("Unsupported response decision.")

    decision_at = datetime.now(timezone.utc).isoformat()
    connection.execute("BEGIN IMMEDIATE")

    try:
        existing = connection.execute(
            """
            SELECT id, requested_by, status
            FROM response_records
            WHERE id = ?
            """,
            (response_id,),
        ).fetchone()

        if existing is None:
            connection.rollback()
            return "not_found"

        if existing["requested_by"] == actor_id:
            connection.rollback()
            return "self_decision"

        if existing["status"] != "pending_approval":
            connection.rollback()
            return "already_decided"

        integrity = verify_response_audit_before_mutation(
            connection,
            response_id,
        )
        if not integrity["valid"]:
            logging.error(
                "Blocked response decision for %s because audit "
                "integrity verification failed: %s",
                response_id,
                integrity["errors"],
            )
            connection.rollback()
            return "audit_integrity_failure"

        cursor = connection.execute(
            """
            UPDATE response_records
            SET
                status = ?,
                decided_by = ?,
                decision_at = ?,
                decision_reason = ?
            WHERE id = ?
              AND status = 'pending_approval'
              AND requested_by != ?
            """,
            (
                decision,
                actor_id,
                decision_at,
                reason,
                response_id,
                actor_id,
            ),
        )

        if cursor.rowcount != 1:
            connection.rollback()
            return "conflict"

        record = connection.execute(
            """
            SELECT alert_id
            FROM response_records
            WHERE id = ?
            """,
            (response_id,),
        ).fetchone()

        event = (
            "response_approved"
            if decision == "approved"
            else "response_rejected"
        )

        append_audit_event(
            connection=connection,
            response_id=response_id,
            alert_id=record["alert_id"],
            event=event,
            actor=actor_id,
            details={
                "previous_status": "pending_approval",
                "new_status": decision,
                "decided_by": actor_id,
                "decision_reason": reason,
                "executed": False,
                "simulated": False,
            },
            created_at=decision_at,
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    checkpoint_written = _write_committed_audit_checkpoint(
        connection,
        response_id,
    )

    return "updated" if checkpoint_written else "checkpoint_pending"


def simulate_response(
    connection,
    response_id: int,
    actor_id: str,
) -> str:
    """
    Simulate an approved dry-run response.

    This function never performs real firewall, operating-system,
    or network operations.
    """

    simulation_at = datetime.now(timezone.utc).isoformat()
    connection.execute("BEGIN IMMEDIATE")

    try:
        record = connection.execute(
            """
            SELECT
                id,
                alert_id,
                action,
                target,
                mode,
                status,
                executed,
                simulated
            FROM response_records
            WHERE id = ?
            """,
            (response_id,),
        ).fetchone()

        if record is None:
            connection.rollback()
            return "not_found"

        if record["simulated"]:
            connection.rollback()
            return "already_simulated"

        if record["status"] != "approved":
            connection.rollback()
            return "not_approved"

        if record["executed"]:
            connection.rollback()
            return "already_executed"

        if (
            record["action"] != "block_ip"
            or record["mode"] != "dry_run"
        ):
            connection.rollback()
            return "unsupported_action"

        integrity = verify_response_audit_before_mutation(
            connection,
            response_id,
        )
        if not integrity["valid"]:
            logging.error(
                "Blocked response simulation for %s because audit "
                "integrity verification failed: %s",
                response_id,
                integrity["errors"],
            )
            connection.rollback()
            return "audit_integrity_failure"

        cursor = connection.execute(
            """
            UPDATE response_records
            SET
                status = 'simulated',
                simulated = 1
            WHERE id = ?
              AND status = 'approved'
              AND simulated = 0
              AND executed = 0
              AND action = 'block_ip'
              AND mode = 'dry_run'
            """,
            (response_id,),
        )

        if cursor.rowcount != 1:
            connection.rollback()
            return "conflict"

        append_audit_event(
            connection=connection,
            response_id=response_id,
            alert_id=record["alert_id"],
            event="response_simulated",
            actor=actor_id,
            details={
                "simulation_mode": "dry_run",
                "action": record["action"],
                "target": record["target"],
                "outcome": "would_block",
                "firewall_modified": False,
                "network_modified": False,
                "operating_system_command_executed": False,
                "executed": False,
                "simulated": True,
            },
            created_at=simulation_at,
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    checkpoint_written = _write_committed_audit_checkpoint(
        connection,
        response_id,
    )

    return "simulated" if checkpoint_written else "checkpoint_pending"


def get_response_history(connection, limit: int = 100):
    rows = connection.execute(
        """
        SELECT *
        FROM response_records
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    return [
        {
            **dict(row),
            "policy_allowed": bool(row["policy_allowed"]),
            "approval_required": bool(row["approval_required"]),
            "executed": bool(row["executed"]),
            "simulated": bool(row["simulated"]),
            "reasons": json.loads(row["reasons"]),
        }
        for row in rows
    ]


def get_response_record(connection, response_id: int):
    row = connection.execute(
        """
        SELECT *
        FROM response_records
        WHERE id = ?
        """,
        (response_id,),
    ).fetchone()

    if row is None:
        return None

    record = dict(row)
    record["policy_allowed"] = bool(record["policy_allowed"])
    record["approval_required"] = bool(record["approval_required"])
    record["executed"] = bool(record["executed"])
    record["simulated"] = bool(record["simulated"])
    record["reasons"] = json.loads(record["reasons"])

    audit_rows = connection.execute(
        """
        SELECT *
        FROM response_audit_log
        WHERE response_id = ?
        ORDER BY id ASC
        """,
        (response_id,),
    ).fetchall()

    record["audit_log"] = [
        {
            **dict(audit),
            "details": json.loads(audit["details"]),
        }
        for audit in audit_rows
    ]

    return record
