from fastapi import APIRouter, Depends, HTTPException

from app.auth import AuthenticatedActor, get_approver_actor
from app.database import get_connection
from app.response.audit import validate_response_audit
from app.response.repository import get_response_record


router = APIRouter(
    prefix="/api/v1/response",
    tags=["Response Audit Integrity"],
)


@router.get("/{response_id}/audit-integrity")
def inspect_response_audit(
    response_id: int,
    actor: AuthenticatedActor = Depends(get_approver_actor),
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

    validation = validate_response_audit(record)

    return {
        "response_id": response_id,
        "status": record["status"],
        "valid": validation["valid"],
        "errors": validation["errors"],
    }