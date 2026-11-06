
import ipaddress

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from app.auth import (
    AuthenticatedActor,
    get_analyst_actor,
    get_approver_actor,
    get_current_actor,
)
from app.database import get_connection
from app.response.engine import ResponseEngine
from app.response.models import (
    ExecutionMode,
    ResponseAction,
    ResponseRequest,
)
from app.response.repository import (
    decide_response,
    get_response_history,
    get_response_record,
    save_response,
    simulate_response,
)


router = APIRouter(
    prefix="/api/v1/response",
    tags=["Automated Response"],
)

response_engine = ResponseEngine()


class ResponsePreviewRequest(BaseModel):
    alert_id: int = Field(gt=0)
    action: ResponseAction
    target: str = Field(min_length=1, max_length=45)

    @field_validator("target", mode="before")
    @classmethod
    def strip_target(cls, value):
        if isinstance(value, str):
            return value.strip()
        return value


class ResponseDecisionRequest(BaseModel):
    reason: str = Field(default="", max_length=500)

    @field_validator("reason")
    @classmethod
    def strip_reason(cls, value):
        return value.strip()


def validate_alert_target(
    alert_source_ip: str | None,
    requested_target: str,
) -> None:
    if not alert_source_ip:
        raise HTTPException(
            status_code=422,
            detail="The alert does not contain a source IP address.",
        )

    try:
        source_address = ipaddress.ip_address(alert_source_ip)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail="The alert contains an invalid source IP address.",
        )

    try:
        target_address = ipaddress.ip_address(requested_target)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail="The response target must be a valid IP address.",
        )

    if target_address != source_address:
        raise HTTPException(
            status_code=422,
            detail=(
                "The response target must match the source IP "
                "associated with the specified alert."
            ),
        )


@router.post("/preview", status_code=201)
def preview_response(
    payload: ResponsePreviewRequest,
    actor: AuthenticatedActor = Depends(get_analyst_actor),
):
    with get_connection() as connection:
        alert = connection.execute(
            """
            SELECT id, source_ip, title, severity, status
            FROM security_alerts
            WHERE id = ?
            """,
            (payload.alert_id,),
        ).fetchone()

        if alert is None:
            raise HTTPException(
                status_code=404,
                detail="The specified security alert does not exist.",
            )

        validate_alert_target(
            alert["source_ip"],
            payload.target,
        )

        request = ResponseRequest(
            alert_id=payload.alert_id,
            action=payload.action,
            target=payload.target,
            mode=ExecutionMode.DRY_RUN,
            requested_by=actor.actor_id,
        )

        result = response_engine.request_approval(request)

        response_id = save_response(
            connection,
            request,
            result,
        )

    return {
        "message": "Response request evaluated and recorded.",
        "response_id": response_id,
        "alert": dict(alert),
        "result": result.to_dict(),
    }


def _process_response_decision(
    response_id: int,
    payload: ResponseDecisionRequest,
    actor: AuthenticatedActor,
    decision: str,
):
    if response_id <= 0:
        raise HTTPException(
            status_code=400,
            detail="response_id must be positive.",
        )

    with get_connection() as connection:
        outcome = decide_response(
            connection=connection,
            response_id=response_id,
            actor_id=actor.actor_id,
            decision=decision,
            reason=payload.reason,
        )

        if outcome == "not_found":
            raise HTTPException(
                status_code=404,
                detail="Response record not found.",
            )

        if outcome == "self_decision":
            raise HTTPException(
                status_code=403,
                detail=(
                    "The requester cannot approve or reject "
                    "their own response request."
                ),
            )

        if outcome == "already_decided":
            raise HTTPException(
                status_code=409,
                detail="This response request has already been decided.",
            )

        if outcome == "audit_integrity_failure":
            raise HTTPException(
                status_code=409,
                detail=(
                    "Response decision blocked because existing audit "
                    "evidence failed integrity verification."
                ),
            )

        if outcome == "conflict":
            raise HTTPException(
                status_code=409,
                detail="The response request could not be updated.",
            )

        record = get_response_record(
            connection,
            response_id,
        )

    return {
        "message": f"Response request {decision}.",
        "response": record,
    }


@router.post("/{response_id}/approve")
def approve_response(
    response_id: int,
    payload: ResponseDecisionRequest,
    actor: AuthenticatedActor = Depends(get_approver_actor),
):
    return _process_response_decision(
        response_id=response_id,
        payload=payload,
        actor=actor,
        decision="approved",
    )


@router.post("/{response_id}/reject")
def reject_response(
    response_id: int,
    payload: ResponseDecisionRequest,
    actor: AuthenticatedActor = Depends(get_approver_actor),
):
    return _process_response_decision(
        response_id=response_id,
        payload=payload,
        actor=actor,
        decision="rejected",
    )


@router.post("/{response_id}/simulate")
def simulate_approved_response(
    response_id: int,
    actor: AuthenticatedActor = Depends(get_analyst_actor),
):
    if response_id <= 0:
        raise HTTPException(
            status_code=400,
            detail="response_id must be positive.",
        )

    with get_connection() as connection:
        outcome = simulate_response(
            connection=connection,
            response_id=response_id,
            actor_id=actor.actor_id,
        )

        if outcome == "not_found":
            raise HTTPException(
                status_code=404,
                detail="Response record not found.",
            )

        if outcome == "already_simulated":
            raise HTTPException(
                status_code=409,
                detail="This response has already been simulated.",
            )

        if outcome == "not_approved":
            raise HTTPException(
                status_code=409,
                detail="Only approved response requests can be simulated.",
            )

        if outcome == "already_executed":
            raise HTTPException(
                status_code=409,
                detail="This response has already been executed.",
            )

        if outcome == "unsupported_action":
            raise HTTPException(
                status_code=422,
                detail="Only approved block_ip dry-run responses are supported.",
            )

        if outcome == "audit_integrity_failure":
            raise HTTPException(
                status_code=409,
                detail=(
                    "Response simulation blocked because existing audit "
                    "evidence failed integrity verification."
                ),
            )

        if outcome == "conflict":
            raise HTTPException(
                status_code=409,
                detail="The response could not be simulated because its state changed.",
            )

        record = get_response_record(
            connection,
            response_id,
        )

    return {
        "message": "Dry-run response simulation completed.",
        "response": record,
    }


@router.get("/history")
def response_history(
    limit: int = Query(default=100, ge=1, le=500),
    actor: AuthenticatedActor = Depends(get_current_actor),
):
    with get_connection() as connection:
        records = get_response_history(
            connection,
            limit=limit,
        )

    return {
        "count": len(records),
        "responses": records,
    }


@router.get("/history/{response_id}")
def response_history_detail(
    response_id: int,
    actor: AuthenticatedActor = Depends(get_current_actor),
):
    if response_id <= 0:
        raise HTTPException(
            status_code=400,
            detail="response_id must be positive.",
        )

    with get_connection() as connection:
        record = get_response_record(
            connection,
            response_id,
        )

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="Response record not found.",
        )

    return record
