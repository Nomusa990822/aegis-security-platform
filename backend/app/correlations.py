from datetime import datetime, timezone
from typing import Literal, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from app.database import get_connection


router = APIRouter(
    prefix="/api/v1/correlations",
    tags=["Correlation Management"]
)


# --------------------------------------------------
# REQUEST MODELS
# --------------------------------------------------

class CorrelationStatusUpdate(BaseModel):
    status: Literal["open", "investigating", "resolved"]
    actor: str = Field(default="analyst", min_length=1, max_length=100)
    details: Optional[str] = Field(default=None, max_length=2000)


class CorrelationAssignment(BaseModel):
    assigned_to: Optional[str] = Field(
        default=None,
        max_length=100
    )
    actor: str = Field(default="analyst", min_length=1, max_length=100)


class CorrelationNoteCreate(BaseModel):
    author: str = Field(
        default="analyst",
        min_length=1,
        max_length=100
    )

    content: str = Field(
        min_length=1,
        max_length=10000
    )

    @field_validator("author", "content")
    @classmethod
    def reject_blank_values(cls, value):
        if not value.strip():
            raise ValueError("This field cannot be empty or whitespace")

        return value.strip()

# --------------------------------------------------
# HELPERS
# --------------------------------------------------

def utc_now():
    return datetime.now(timezone.utc).isoformat()


def get_case_or_404(connection, correlation_id):
    case = connection.execute(
        """
        SELECT *
        FROM security_correlations
        WHERE id = ?
        """,
        (correlation_id,)
    ).fetchone()

    if case is None:
        raise HTTPException(
            status_code=404,
            detail="Correlation case not found"
        )

    return case


def record_case_activity(
    connection,
    correlation_id,
    action,
    summary,
    actor,
    details=None,
    previous_value=None,
    new_value=None
):
    timestamp = utc_now()

    connection.execute(
        """
        INSERT INTO correlation_timeline (
            correlation_id,
            action,
            summary,
            details,
            actor,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            correlation_id,
            action,
            summary,
            details,
            actor,
            timestamp
        )
    )

    connection.execute(
        """
        INSERT INTO correlation_audit_log (
            correlation_id,
            action,
            actor,
            previous_value,
            new_value,
            details,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            correlation_id,
            action,
            actor,
            previous_value,
            new_value,
            details,
            timestamp
        )
    )


# --------------------------------------------------
# LIST CORRELATION CASES
# --------------------------------------------------

@router.get("")
def get_correlations(
    status: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000)
):
    allowed_statuses = {
        "open",
        "investigating",
        "resolved"
    }

    allowed_severities = {
        "low",
        "medium",
        "high",
        "critical"
    }

    if status and status.lower() not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail="Invalid status filter"
        )

    if severity and severity.lower() not in allowed_severities:
        raise HTTPException(
            status_code=400,
            detail="Invalid severity filter"
        )

    query = """
        SELECT *
        FROM security_correlations
        WHERE 1 = 1
    """

    parameters = []

    if status:
        query += " AND status = ?"
        parameters.append(status.lower())

    if severity:
        query += " AND severity = ?"
        parameters.append(severity.lower())

    query += " ORDER BY created_at DESC LIMIT ?"
    parameters.append(limit)

    with get_connection() as connection:
        rows = connection.execute(
            query,
            parameters
        ).fetchall()

    return {
        "count": len(rows),
        "correlations": [dict(row) for row in rows]
    }


# --------------------------------------------------
# VIEW A CORRELATION CASE
# --------------------------------------------------

@router.get("/{correlation_id}")
def get_correlation(correlation_id: int):

    with get_connection() as connection:

        case = get_case_or_404(
            connection,
            correlation_id
        )

        alerts = connection.execute(
            """
            SELECT
                a.*,
                ca.linked_at
            FROM security_correlation_alerts ca
            JOIN security_alerts a
                ON a.id = ca.alert_id
            WHERE ca.correlation_id = ?
            ORDER BY ca.linked_at ASC
            """,
            (correlation_id,)
        ).fetchall()

        notes = connection.execute(
            """
            SELECT *
            FROM correlation_notes
            WHERE correlation_id = ?
            ORDER BY created_at DESC
            """,
            (correlation_id,)
        ).fetchall()

    return {
        "correlation": dict(case),
        "alert_count": len(alerts),
        "alerts": [dict(alert) for alert in alerts],
        "note_count": len(notes),
        "notes": [dict(note) for note in notes]
    }


# --------------------------------------------------
# UPDATE CASE STATUS
# --------------------------------------------------

@router.patch("/{correlation_id}/status")
def update_correlation_status(
    correlation_id: int,
    payload: CorrelationStatusUpdate
):

    with get_connection() as connection:

        case = get_case_or_404(
            connection,
            correlation_id
        )

        previous_status = case["status"]

        if previous_status == payload.status:
            return {
                "message": "Case already has this status",
                "correlation_id": correlation_id,
                "status": previous_status
            }

        timestamp = utc_now()

        connection.execute(
            """
            UPDATE security_correlations
            SET status = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                payload.status,
                timestamp,
                correlation_id
            )
        )

        record_case_activity(
            connection,
            correlation_id,
            "status_changed",
            f"Case status changed from {previous_status} to {payload.status}",
            payload.actor,
            payload.details,
            previous_status,
            payload.status
        )

        connection.commit()

    return {
        "message": "Correlation case status updated",
        "correlation_id": correlation_id,
        "previous_status": previous_status,
        "new_status": payload.status
    }


# --------------------------------------------------
# ASSIGN ANALYST
# --------------------------------------------------

@router.patch("/{correlation_id}/assignment")
def assign_correlation_case(
    correlation_id: int,
    payload: CorrelationAssignment
):

    with get_connection() as connection:

        case = get_case_or_404(
            connection,
            correlation_id
        )

        previous_assignment = case["assigned_to"]
        new_assignment = (
            payload.assigned_to.strip()
            if payload.assigned_to
            else None
        )

        timestamp = utc_now()

        if previous_assignment == new_assignment:
            return {
                "message": "Case is already assigned this way",
                "correlation_id": correlation_id,
                "assigned_to": previous_assignment
            }

        connection.execute(
            """
            UPDATE security_correlations
            SET assigned_to = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                new_assignment,
                timestamp,
                correlation_id
            )
        )

        record_case_activity(
            connection,
            correlation_id,
            "analyst_assigned",
            (
                f"Case assigned to {new_assignment}"
                if new_assignment
                else "Case assignment removed"
            ),
            payload.actor,
            previous_value=previous_assignment,
            new_value=new_assignment
        )

        connection.commit()

    return {
        "message": "Correlation case assignment updated",
        "correlation_id": correlation_id,
        "previous_assignment": previous_assignment,
        "assigned_to": new_assignment
    }


# --------------------------------------------------
# ADD INVESTIGATION NOTE
# --------------------------------------------------

@router.post("/{correlation_id}/notes")
def add_correlation_note(
    correlation_id: int,
    payload: CorrelationNoteCreate
):

    with get_connection() as connection:

        get_case_or_404(
            connection,
            correlation_id
        )

        timestamp = utc_now()

        cursor = connection.execute(
            """
            INSERT INTO correlation_notes (
                correlation_id,
                author,
                content,
                created_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                correlation_id,
                payload.author,
                payload.content.strip(),
                timestamp
            )
        )

        note_id = cursor.lastrowid

        record_case_activity(
            connection,
            correlation_id,
            "note_added",
            "Investigation note added",
            payload.author,
            payload.content.strip()
        )

        connection.commit()

    return {
        "message": "Investigation note added",
        "note_id": note_id,
        "correlation_id": correlation_id,
        "created_at": timestamp
    }


# --------------------------------------------------
# VIEW CASE TIMELINE
# --------------------------------------------------

@router.get("/{correlation_id}/timeline")
def get_correlation_timeline(correlation_id: int):

    with get_connection() as connection:

        get_case_or_404(
            connection,
            correlation_id
        )

        rows = connection.execute(
            """
            SELECT *
            FROM correlation_timeline
            WHERE correlation_id = ?
            ORDER BY created_at ASC, id ASC
            """,
            (correlation_id,)
        ).fetchall()

    return {
        "correlation_id": correlation_id,
        "count": len(rows),
        "timeline": [dict(row) for row in rows]
    }


# --------------------------------------------------
# VIEW CASE AUDIT HISTORY
# --------------------------------------------------

@router.get("/{correlation_id}/audit")
def get_correlation_audit(correlation_id: int):

    with get_connection() as connection:

        get_case_or_404(
            connection,
            correlation_id
        )

        rows = connection.execute(
            """
            SELECT *
            FROM correlation_audit_log
            WHERE correlation_id = ?
            ORDER BY created_at ASC, id ASC
            """,
            (correlation_id,)
        ).fetchall()

    return {
        "correlation_id": correlation_id,
        "count": len(rows),
        "audit_history": [dict(row) for row in rows]
    }
