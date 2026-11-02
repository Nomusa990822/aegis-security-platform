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

    return {"alert": dict(alert)}


@router.patch("/{alert_id}/status")
def update_alert_status(
    alert_id: int,
    update: AlertStatusUpdate
):

    with get_connection() as connection:

        existing_alert = connection.execute(
            """
            SELECT *
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

        connection.commit()

    return {
        "message": "Alert status updated and verified",
        "previous_status": previous_status,
        "alert": dict(updated_alert)
    }

