
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from app.database import get_connection


router = APIRouter(
    prefix="/api/v1/correlations",
    tags=["Correlation Management"]
)


@router.get("")
def get_correlations(
    status: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000)
):
    """
    Retrieve correlation cases with optional status and severity filters.
    """

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
        "correlations": [
            dict(row) for row in rows
        ]
    }


@router.get("/{correlation_id}")
def get_correlation(correlation_id: int):

    with get_connection() as connection:

        correlation = connection.execute(
            """
            SELECT *
            FROM security_correlations
            WHERE id = ?
            """,
            (correlation_id,)
        ).fetchone()

        if correlation is None:
            raise HTTPException(
                status_code=404,
                detail="Correlation case not found"
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

    return {
        "correlation": dict(correlation),
        "alert_count": len(alerts),
        "alerts": [
            dict(alert) for alert in alerts
        ]
    }
