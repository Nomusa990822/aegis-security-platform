import sqlite3

from datetime import datetime, timezone
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException

from app.auth import AuthenticatedActor, get_analyst_actor, get_current_actor
from pydantic import BaseModel, ConfigDict, Field

from app.database import get_connection
from app.intelligence.mitre import MITREAttackMapper


router = APIRouter(
    prefix="/api/v1/alerts",
    tags=["Alert Management"],
    dependencies=[Depends(get_current_actor)],
)


def current_timestamp():
    return datetime.now(timezone.utc).isoformat()


def ensure_alert_exists(connection, alert_id):
    alert = connection.execute(
        """
        SELECT *
        FROM security_alerts
        WHERE id = ?
        """,
        (alert_id,)
    ).fetchone()

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    return alert


def record_timeline(
    connection,
    alert_id,
    action,
    summary,
    details=None,
    actor="analyst"
):
    connection.execute(
        """
        INSERT INTO incident_timeline (
            alert_id,
            action,
            summary,
            details,
            actor,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            alert_id,
            action,
            summary,
            details,
            actor,
            current_timestamp()
        )
    )


def record_audit(
    connection,
    alert_id,
    action,
    previous_value=None,
    new_value=None,
    details=None,
    actor="analyst"
):
    connection.execute(
        """
        INSERT INTO alert_audit_log (
            alert_id,
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
            alert_id,
            action,
            actor,
            previous_value,
            new_value,
            details,
            current_timestamp()
        )
    )


class AlertStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["open", "investigating", "resolved"]


class InvestigationNote(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str = Field(min_length=1, max_length=5000)


class EvidenceLink(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: int = Field(gt=0)
    analyst_note: str | None = Field(default=None, max_length=1000)


@router.get("/{alert_id}/investigation")
def get_investigation(alert_id: int):

    with get_connection() as connection:

        alert = ensure_alert_exists(connection, alert_id)

        notes = connection.execute(
            """
            SELECT *
            FROM incident_notes
            WHERE alert_id = ?
            ORDER BY id DESC
            """,
            (alert_id,)
        ).fetchall()

        timeline = connection.execute(
            """
            SELECT *
            FROM incident_timeline
            WHERE alert_id = ?
            ORDER BY id ASC
            """,
            (alert_id,)
        ).fetchall()

        evidence = connection.execute(
            """
            SELECT
                ie.id AS evidence_id,
                ie.alert_id,
                ie.event_id,
                ie.analyst_note,
                ie.linked_by,
                ie.linked_at,
                se.event_type,
                se.source_ip,
                se.username,
                se.outcome,
                se.description,
                se.occurred_at,
                se.received_at
            FROM incident_evidence AS ie
            JOIN security_events AS se
                ON ie.event_id = se.id
            WHERE ie.alert_id = ?
            ORDER BY ie.id DESC
            """,
            (alert_id,)
        ).fetchall()

        audit_log = connection.execute(
            """
            SELECT *
            FROM alert_audit_log
            WHERE alert_id = ?
            ORDER BY id DESC
            """,
            (alert_id,)
        ).fetchall()

        return {
            "alert": dict(alert),
            "mitre": MITREAttackMapper.get_rule_mapping(
                alert["detection_rule"]
            ),
            "notes": [dict(row) for row in notes],
            "timeline": [dict(row) for row in timeline],
            "evidence": [dict(row) for row in evidence],
            "audit_log": [dict(row) for row in audit_log]
        }


@router.post("/{alert_id}/notes", status_code=201)
def add_investigation_note(
    alert_id: int,
    note: InvestigationNote,
    actor: AuthenticatedActor = Depends(get_analyst_actor),
):

    content = note.content.strip()

    if not content:
        raise HTTPException(
            status_code=422,
            detail="Investigation note cannot be empty"
        )

    with get_connection() as connection:

        ensure_alert_exists(connection, alert_id)

        timestamp = current_timestamp()

        cursor = connection.execute(
            """
            INSERT INTO incident_notes (
                alert_id,
                author,
                content,
                created_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                alert_id,
                actor.actor_id,
                content,
                timestamp
            )
        )

        note_id = cursor.lastrowid

        record_timeline(
            connection,
            alert_id,
            "note_added",
            "Investigation note added",
            content,
            actor=actor.actor_id,
        )

        record_audit(
            connection,
            alert_id,
            "note_added",
            details=f"Investigation note ID: {note_id}",
            actor=actor.actor_id,
        )

        connection.commit()

        saved_note = connection.execute(
            """
            SELECT *
            FROM incident_notes
            WHERE id = ?
            """,
            (note_id,)
        ).fetchone()

    return {
        "message": "Investigation note saved",
        "note": dict(saved_note)
    }


@router.post("/{alert_id}/evidence", status_code=201)
def link_evidence(
    alert_id: int,
    evidence: EvidenceLink,
    actor: AuthenticatedActor = Depends(get_analyst_actor),
):

    with get_connection() as connection:

        ensure_alert_exists(connection, alert_id)

        event = connection.execute(
            """
            SELECT *
            FROM security_events
            WHERE id = ?
            """,
            (evidence.event_id,)
        ).fetchone()

        if event is None:
            raise HTTPException(
                status_code=404,
                detail="Security event not found"
            )

        existing = connection.execute(
            """
            SELECT id
            FROM incident_evidence
            WHERE alert_id = ? AND event_id = ?
            """,
            (alert_id, evidence.event_id)
        ).fetchone()

        if existing is not None:
            raise HTTPException(
                status_code=409,
                detail="This event is already linked to the incident"
            )

        timestamp = current_timestamp()

        cursor = connection.execute(
            """
            INSERT INTO incident_evidence (
                alert_id,
                event_id,
                analyst_note,
                linked_by,
                linked_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                alert_id,
                evidence.event_id,
                evidence.analyst_note,
                actor.actor_id,
                timestamp
            )
        )

        evidence_id = cursor.lastrowid

        record_timeline(
            connection,
            alert_id,
            "evidence_linked",
            f"Security event #{evidence.event_id} linked as evidence",
            evidence.analyst_note,
            actor=actor.actor_id,
        )

        record_audit(
            connection,
            alert_id,
            "evidence_linked",
            details=(
                f"Evidence ID: {evidence_id}; "
                f"Security event ID: {evidence.event_id}"
            ),
            actor=actor.actor_id,
        )

        connection.commit()

        saved_evidence = connection.execute(
            """
            SELECT *
            FROM incident_evidence
            WHERE id = ?
            """,
            (evidence_id,)
        ).fetchone()

    return {
        "message": "Evidence linked to incident",
        "evidence": dict(saved_evidence)
    }


@router.patch("/{alert_id}/status")
def update_alert_status(
    alert_id: int,
    update: AlertStatusUpdate,
    actor: AuthenticatedActor = Depends(get_analyst_actor),
):

    with get_connection() as connection:

        existing_alert = ensure_alert_exists(
            connection,
            alert_id
        )

        previous_status = existing_alert["status"]

        cursor = connection.execute(
            """
            UPDATE security_alerts
            SET status = ?
            WHERE id = ?
            """,
            (update.status, alert_id)
        )

        if cursor.rowcount != 1:
            raise HTTPException(
                status_code=500,
                detail="Alert status update failed"
            )

        updated_alert = connection.execute(
            """
            SELECT *
            FROM security_alerts
            WHERE id = ?
            """,
            (alert_id,)
        ).fetchone()

        if updated_alert["status"] != update.status:
            raise HTTPException(
                status_code=500,
                detail="Alert status verification failed"
            )

        # Record status changes in the incident history.
        if previous_status != update.status:

            record_timeline(
                connection,
                alert_id,
                "status_changed",
                f"Alert status changed from {previous_status} to {update.status}",
                f"{previous_status} -> {update.status}",
                actor=actor.actor_id,
            )

            record_audit(
                connection,
                alert_id,
                "status_changed",
                previous_value=previous_status,
                new_value=update.status,
                actor=actor.actor_id,
            )

        connection.commit()

    return {
        "message": "Alert status updated and verified",
        "previous_status": previous_status,
        "alert": dict(updated_alert)
    }


@router.get("/{alert_id}")
def get_alert(alert_id: int):

    with get_connection() as connection:

        alert = ensure_alert_exists(connection, alert_id)

    return {
        "alert": dict(alert)
    }
