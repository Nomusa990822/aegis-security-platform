
import json
from datetime import datetime, timezone

from app.response.models import ResponseRequest, ResponseResult


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

    connection.execute(
        """
        INSERT INTO response_audit_log (
            response_id,
            alert_id,
            event,
            actor,
            details,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            response_id,
            request.alert_id,
            "response_request_created",
            request.requested_by,
            json.dumps({
                "status": result.status.value,
                "action": request.action.value,
                "target": request.target,
                "policy_allowed": result.policy_allowed,
                "approval_required": result.approval_required,
                "executed": result.executed,
                "simulated": result.simulated,
            }),
            created_at,
        ),
    )

    connection.commit()
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
        existing = connection.execute(
            """
            SELECT id, requested_by, status
            FROM response_records
            WHERE id = ?
            """,
            (response_id,),
        ).fetchone()

        if existing is None:
            return "not_found"

        if existing["requested_by"] == actor_id:
            return "self_decision"

        if existing["status"] != "pending_approval":
            return "already_decided"

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

    connection.execute(
        """
        INSERT INTO response_audit_log (
            response_id,
            alert_id,
            event,
            actor,
            details,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            response_id,
            record["alert_id"],
            event,
            actor_id,
            json.dumps({
                "previous_status": "pending_approval",
                "new_status": decision,
                "decided_by": actor_id,
                "decision_reason": reason,
                "executed": False,
                "simulated": False,
            }),
            decision_at,
        ),
    )

    connection.commit()
    return "updated"


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

        connection.execute(
            """
            INSERT INTO response_audit_log (
                response_id,
                alert_id,
                event,
                actor,
                details,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                response_id,
                record["alert_id"],
                "response_simulated",
                actor_id,
                json.dumps({
                    "simulation_mode": "dry_run",
                    "action": record["action"],
                    "target": record["target"],
                    "outcome": "would_block",
                    "firewall_modified": False,
                    "network_modified": False,
                    "operating_system_command_executed": False,
                    "executed": False,
                    "simulated": True,
                }),
                simulation_at,
            ),
        )

        connection.commit()
        return "simulated"

    except Exception:
        connection.rollback()
        raise


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
