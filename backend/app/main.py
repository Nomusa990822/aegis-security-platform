import ipaddress
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Response

from app.auth import AuthenticatedActor, get_analyst_actor, get_current_actor
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from app.database import get_connection, initialize_database
from app.idempotency import initialize_idempotency_schema
from app.detection.engine import evaluate_event
from app.detection.registry import get_detection_rules
from app.detection.correlation import correlate_alerts
from app.alerts import router as alerts_router
from app.correlations import router as correlations_router
from app.intelligence.router import router as intelligence_router
from app.intelligence.alert_enrichment import AlertIntelligenceService
from app.intelligence.mitre_router import router as mitre_router
from app.response.router import router as response_router
from app.response.audit_router import router as response_audit_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    initialize_idempotency_schema()
    yield


app = FastAPI(
    title="AEGIS Security Platform",
    description="Autonomous Threat Detection and Response Platform",
    version="0.4.0",
    lifespan=lifespan,
)


app.mount(
    "/dashboard",
    StaticFiles(
        directory=Path(__file__).resolve().parent / "static",
        html=True,
    ),
    name="dashboard",
)

app.include_router(alerts_router)
app.include_router(correlations_router)
app.include_router(intelligence_router)
app.include_router(mitre_router)
app.include_router(response_router)
app.include_router(response_audit_router)

alert_intelligence_service = AlertIntelligenceService()


class SecurityEvent(BaseModel):
    event_type: str = Field(min_length=1, max_length=100)

    source_system: str = Field(
        default="default",
        min_length=1,
        max_length=100,
    )
    external_event_id: Optional[str] = Field(
        default=None,
        max_length=256,
    )

    source_ip: Optional[str] = Field(default=None, max_length=45)
    username: Optional[str] = Field(default=None, max_length=256)
    outcome: Optional[str] = Field(default=None, max_length=50)

    destination_ip: Optional[str] = Field(default=None, max_length=45)
    destination_port: Optional[int] = Field(
        default=None,
        ge=1,
        le=65535,
    )
    protocol: Optional[str] = Field(default=None, max_length=20)

    description: str = Field(default="", max_length=2000)
    occurred_at: Optional[datetime] = None

    @field_validator("event_type")
    @classmethod
    def validate_event_type(cls, value):
        value = value.strip().lower()

        if not value:
            raise ValueError("event_type cannot be blank")

        return value

    @field_validator("source_system")
    @classmethod
    def validate_source_system(cls, value):
        value = value.strip().lower()

        if not value:
            raise ValueError("source_system cannot be blank")

        return value

    @field_validator("external_event_id")
    @classmethod
    def validate_external_event_id(cls, value):
        if value is None:
            return None

        value = value.strip()

        if not value:
            raise ValueError("external_event_id cannot be blank")

        return value

    @field_validator("outcome", "protocol")
    @classmethod
    def normalise_optional_values(cls, value):
        if value is None:
            return value

        value = value.strip().lower()

        if not value:
            raise ValueError("Value cannot be blank")

        return value

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_ip_addresses(cls, value):
        if value is None:
            return value

        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError as error:
            raise ValueError(
                "Must be a valid IPv4 or IPv6 address"
            ) from error


@app.get("/")
def home():
    return {
        "platform": "AEGIS",
        "status": "operational",
        "version": "0.4.0",
    }


@app.get("/api/v1/auth/me")
def current_session(
    actor: AuthenticatedActor = Depends(get_current_actor),
):
    return {
        "actor_id": actor.actor_id,
        "role": actor.role,
    }


@app.get("/api/v1/health")
def health():
    return {
        "status": "healthy",
        "database": "connected",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/v1/events", status_code=201)
async def ingest_event(
    event: SecurityEvent,
    response: Response,
    actor: AuthenticatedActor = Depends(get_analyst_actor),
):
    received_at = datetime.now(timezone.utc)
    occurred_at = event.occurred_at or received_at

    try:
        with get_connection() as connection:

            if event.external_event_id is not None:
                cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO security_events (
                        event_type,
                        source_ip,
                        username,
                        outcome,
                        description,
                        occurred_at,
                        received_at,
                        destination_ip,
                        destination_port,
                        protocol,
                        source_system,
                        external_event_id
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        event.protocol,
                        event.source_system,
                        event.external_event_id,
                    ),
                )

                if cursor.rowcount == 0:
                    existing = connection.execute(
                        """
                        SELECT id
                        FROM security_events
                        WHERE source_system = ?
                        AND external_event_id = ?
                        """,
                        (
                            event.source_system,
                            event.external_event_id,
                        ),
                    ).fetchone()

                    if existing is None:
                        raise RuntimeError(
                            "Unable to resolve duplicate event identity"
                        )

                    connection.commit()
                    response.status_code = 200

                    return {
                        "message": "Duplicate event ignored",
                        "event_id": existing["id"],
                        "duplicate": True,
                        "detection": None,
                        "detections": [],
                        "detection_count": 0,
                        "correlation": None,
                        "intelligence_enrichments": [],
                    }

                event_id = cursor.lastrowid

            else:
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
                        protocol,
                        source_system,
                        external_event_id
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        event.protocol,
                        event.source_system,
                        None,
                    ),
                )

                event_id = cursor.lastrowid

            event_record = {
                "event_type": event.event_type,
                "source_ip": event.source_ip,
                "username": event.username,
                "outcome": event.outcome,
                "destination_ip": event.destination_ip,
                "destination_port": event.destination_port,
                "protocol": event.protocol,
            }

            detections = evaluate_event(
                connection,
                event_record,
            )

            correlation = None

            if detections and event.source_ip:
                correlation = correlate_alerts(
                    connection,
                    event.source_ip,
                )

            connection.commit()

        
        intelligence_enrichments = []

        for detection in detections:
            alert_id = detection.get("alert_id")

            if alert_id is None:
                continue

            try:
                enrichment_result = (
                    await alert_intelligence_service.enrich_alert(
                        alert_id=alert_id,
                        source_ip=event.source_ip,
                    )
                )

                intelligence_enrichments.append(
                    enrichment_result
                )

            except Exception:
                # Event ingestion and detection have already been committed.
                # Enrichment is supplementary and must not turn a successful
                # ingestion into an HTTP 500 response.
                intelligence_enrichments.append(
                    {
                        "alert_id": alert_id,
                        "status": "failed",
                        "message": "Threat intelligence enrichment failed",
                    }
                )


        return {
            "message": "Security event ingested",
            "event_id": event_id,
            "duplicate": False,
            "detection": detections[0] if detections else None,
            "detections": detections,
            "detection_count": len(detections),
            "correlation": correlation,
            "intelligence_enrichments": intelligence_enrichments,
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail="Unable to process security event",
        ) from error


@app.get("/api/v1/events")
def get_events(
    limit: int = 100,
    actor: AuthenticatedActor = Depends(get_current_actor),
):
    if not 1 <= limit <= 1000:
        raise HTTPException(
            status_code=400,
            detail="limit must be between 1 and 1000",
        )

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM security_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return {
        "count": len(rows),
        "events": [dict(row) for row in rows],
    }


@app.get("/api/v1/alerts")
def get_alerts(
    actor: AuthenticatedActor = Depends(get_current_actor),
):
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
        "alerts": [dict(row) for row in rows],
    }


@app.get("/api/v1/detection/rules")
def get_detection_rules_endpoint(
    actor: AuthenticatedActor = Depends(get_current_actor),
):
    rules = get_detection_rules()

    return {
        "count": len(rules),
        "rules": rules,
    }
