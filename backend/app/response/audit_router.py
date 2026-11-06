
from fastapi import APIRouter, Depends, HTTPException

from app.auth import AuthenticatedActor, get_approver_actor
from app.database import get_connection
from app.response.audit import validate_response_audit
from app.response.audit_chain import verify_hash_chain
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

        chain_head = connection.execute(
            """
            SELECT event_count, final_hash
            FROM response_audit_chain_heads
            WHERE response_id = ?
            """,
            (response_id,),
        ).fetchone()

    lifecycle_validation = validate_response_audit(record)
    chain_validation = verify_hash_chain(record["audit_log"])

    errors = [
        *lifecycle_validation["errors"],
        *chain_validation["errors"],
    ]

    if chain_head is None:
        errors.append("Audit chain head is missing.")
    else:
        if chain_head["event_count"] != chain_validation["event_count"]:
            errors.append(
                "Audit chain event count does not match its chain head."
            )

        if chain_head["final_hash"] != chain_validation["final_hash"]:
            errors.append(
                "Audit chain final hash does not match its chain head."
            )

    return {
        "response_id": response_id,
        "status": record["status"],
        "valid": not errors,
        "chain_valid": (
            chain_validation["valid"]
            and chain_head is not None
            and chain_head["event_count"] == chain_validation["event_count"]
            and chain_head["final_hash"] == chain_validation["final_hash"]
        ),
        "event_count": chain_validation["event_count"],
        "final_hash": chain_validation["final_hash"],
        "errors": errors,
    }
