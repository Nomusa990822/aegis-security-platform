from fastapi import APIRouter, Depends, HTTPException

from app.auth import AuthenticatedActor, get_approver_actor
from app.database import get_connection
from app.response.audit import validate_response_audit
from app.response.audit_chain import verify_hash_chain
from app.response.audit_checkpoint import verify_audit_checkpoint
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

    chain_head_valid = False

    if chain_head is None:
        errors.append("Audit chain head is missing.")
    else:
        count_matches = (
            chain_head["event_count"]
            == chain_validation["event_count"]
        )
        hash_matches = (
            chain_head["final_hash"]
            == chain_validation["final_hash"]
        )

        if not count_matches:
            errors.append(
                "Audit chain event count does not match its chain head."
            )

        if not hash_matches:
            errors.append(
                "Audit chain final hash does not match its chain head."
            )

        chain_head_valid = count_matches and hash_matches

    chain_valid = (
        chain_validation["valid"]
        and chain_head_valid
    )

    if chain_head is None:
        checkpoint_validation = {
            "valid": False,
            "errors": [
                "Cannot verify external checkpoint without a chain head."
            ],
            "checkpoint": None,
        }
    else:
        checkpoint_validation = verify_audit_checkpoint(
            response_id=response_id,
            event_count=chain_head["event_count"],
            final_hash=chain_head["final_hash"],
        )

    errors.extend(checkpoint_validation["errors"])

    checkpoint_valid = checkpoint_validation["valid"]

    return {
        "response_id": response_id,
        "status": record["status"],
        "valid": (
            not errors
            and chain_valid
            and checkpoint_valid
        ),
        "chain_valid": chain_valid,
        "checkpoint_valid": checkpoint_valid,
        "event_count": chain_validation["event_count"],
        "final_hash": chain_validation["final_hash"],
        "errors": errors,
    }