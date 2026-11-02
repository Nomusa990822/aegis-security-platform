
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.database import get_connection


router = APIRouter(
    prefix="/api/v1/alerts",
    tags=["Alert Management"]
)


class AlertStatusUpdate(BaseModel):
    status: Literal["open", "investigating", "resolved"]


@router.get("/{alert_id}")
def get_alert(alert_id: int):
    """Retrieve an individual security alert."""

    with get_connection() as connection:
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

    return {
        "alert": dict(alert)
    }


@router.patch("/{alert_id}/status")
def update_alert_status(
    alert_id: int,
    update: AlertStatusUpdate
):
    """Update the investigation status of an alert."""

    with get_connection() as connection:

        existing_alert = connection.execute(
            """
            SELECT id, status
            FROM security_alerts
            WHERE id = ?
            """,
            (alert_id,)
        ).fetchone()

        if existing_alert is None:
            raise HTTPException(
                status_code=404,
                detail="Alert not found"
            )

        connection.execute(
            """
            UPDATE security_alerts
            SET status = ?
            WHERE id = ?
            """,
            (update.status, alert_id)
        )

        connection.commit()

        updated_alert = connection.execute(
            """
            SELECT *
            FROM security_alerts
            WHERE id = ?
            """,
            (alert_id,)
        ).fetchone()

    return {
        "message": "Alert status updated successfully",
        "previous_status": existing_alert["status"],
        "alert": dict(updated_alert)
    }
