from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from app.database import get_connection, initialize_database
from app.detection.engine import evaluate_event
from app.detection.registry import get_detection_rules
from app.detection.correlation import correlate_alerts
from app.alerts import router as alerts_router
from app.correlations import router as correlations_router


app = FastAPI(
    title="AEGIS Security Platform",
    description="Autonomous Threat Detection and Response Platform",
    version="0.4.0"
)


app.mount(
    "/dashboard",
    StaticFiles(
        directory=Path(__file__).resolve().parent / "static",
        html=True
    ),
    name="dashboard"
)

app.include_router(alerts_router)
app.include_router(correlations_router)


class SecurityEvent(BaseModel):

    event_type: str = Field(min_length=1, max_length=100)

    source_ip: Optional[str] = None
    username: Optional[str] = None
    outcome: Optional[str] = None

    destination_ip: Optional[str] = None
    destination_port: Optional[int] = Field(
        default=None,
        ge=1,
        le=65535
    )
    protocol: Optional[str] = Field(
        default=None,
        max_length=20
    )

    description: str = Field(default="", max_length=2000)
    occurred_at: Optional[datetime] = None

    @field_validator("event_type", "outcome", "protocol")
    @classmethod
    def normalise_values(cls, value):
        if value is None:
            return value
        return value.strip().lower()


@app.on_event("startup")
def startup():
    initialize_database()


@app.get("/")
def home():
    return {
        "platform": "AEGIS",
        "status": "operational",
        "version": "0.4.0"
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
                    received_at,
                    destination_ip,
                    destination_port,
                    protocol
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_type,
                    event.source_ip,
                    event.username,
                    event.outcome,
                    event.description,
                    occurred_at.isoformat(),
                    received_at.isoformat(),
                    event.destination_ip,
                    event.destination_port,
                    event.protocol
                )
            )

            event_id = cursor.lastrowid

            event_record = {
                "event_type": event.event_type,
                "source_ip": event.source_ip,
                "username": event.username,
                "outcome": event.outcome,
                "destination_ip": event.destination_ip,
                "destination_port": event.destination_port,
                "protocol": event.protocol
            }

            detections = evaluate_event(
                connection,
                event_record
            )

            correlation = None

            if detections and event.source_ip:
                correlation = correlate_alerts(
                    connection,
                    event.source_ip
                )

            connection.commit()

            return {
                "message": "Security event ingested",
                "event_id": event_id,
                "detection": detections[0] if detections else None,
                "detections": detections,
                "detection_count": len(detections),
                "correlation": correlation
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
            detail="limit must be between 1 and 1000"
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


@app.get("/api/v1/detection/rules")
def get_detection_rules_endpoint():

    rules = get_detection_rules()

    return {
        "count": len(rules),
        "rules": rules
    }
