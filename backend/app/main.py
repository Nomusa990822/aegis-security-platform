from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.database import (
    get_connection,
    initialize_database
)

app = FastAPI(
    title="AEGIS Security Platform",
    description="Autonomous Threat Detection and Response Platform",
    version="0.1.0"
)


class SecurityEvent(BaseModel):
    event_type: str = Field(min_length=1, max_length=100)
    source_ip: Optional[str] = None
    username: Optional[str] = None
    outcome: Optional[str] = None
    description: str = Field(default="", max_length=2000)
    occurred_at: Optional[datetime] = None


@app.on_event("startup")
def startup():
    initialize_database()


@app.get("/")
def home():
    return {
        "platform": "AEGIS",
        "status": "operational",
        "version": "0.1.0"
    }


@app.get("/api/v1/health")
def health():
    return {
        "status": "healthy",
        "database": "connected",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/api/v1/events", status_code=201)
def ingest_event(event: SecurityEvent):

    received_at = datetime.now(timezone.utc)
    occurred_at = event.occurred_at or received_at

    try:
        with get_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO security_events (
                    event_type,
                    source_ip,
                    username,
                    outcome,
                    description,
                    occurred_at,
                    received_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_type,
                    event.source_ip,
                    event.username,
                    event.outcome,
                    event.description,
                    occurred_at.isoformat(),
                    received_at.isoformat()
                )
            )

            event_id = cursor.lastrowid

            connection.commit()

        return {
            "message": "Security event successfully ingested",
            "event_id": event_id,
            "event_type": event.event_type
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail="Unable to process security event"
        ) from error


@app.get("/api/v1/events")
def get_events(limit: int = 100):

    if not 1 <= limit <= 1000:
        raise HTTPException(
            status_code=400,
            detail="Limit must be between 1 and 1000"
        )

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM security_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        ).fetchall()

    return {
        "count": len(rows),
        "events": [dict(row) for row in rows]
    }


@app.get("/api/v1/alerts")
def get_alerts():

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM security_alerts
            ORDER BY id DESC
            """
        ).fetchall()

    return {
        "count": len(rows),
        "alerts": [dict(row) for row in rows]
    }
