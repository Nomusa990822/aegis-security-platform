
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
            FOREIGN KEY (alert_id)
                REFERENCES security_alerts(id)
                ON DELETE CASCADE
        )
    """)

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
            "response_preview_created",
            request.requested_by,
            json.dumps({
                "status": result.status.value,
                "action": request.action.value,
                "target": request.target,
                "executed": result.executed,
                "simulated": result.simulated,
            }),
            created_at,
        ),
    )

    connection.commit()
    return response_id


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
