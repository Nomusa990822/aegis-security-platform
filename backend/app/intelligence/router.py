from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth import get_current_actor

from app.intelligence.enrichment import (
    ThreatIntelligenceEnrichmentService,
)
from app.intelligence.models import IPAddressRequest
from app.intelligence.repository import IntelligenceRepository


router = APIRouter(
    prefix="/api/v1/intelligence",
    tags=["Threat Intelligence"],
    dependencies=[Depends(get_current_actor)],
)

enrichment_service = ThreatIntelligenceEnrichmentService()
intelligence_repository = IntelligenceRepository()


@router.post("/ip")
async def enrich_ip(request: IPAddressRequest):
    """
    Enrich an IPv4 or IPv6 address with threat intelligence.
    """

    try:
        assessment = await enrichment_service.enrich_ip(
            request.ip_address
        )

        assessment_id = intelligence_repository.save_assessment(
            assessment
        )

        return {
            "message": "IP intelligence assessment completed",
            "assessment_id": assessment_id,
            "assessment": assessment.model_dump(mode="json"),
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail="Unable to complete IP intelligence assessment",
        ) from error


@router.get("/ip/{ip_address:path}")
def get_ip_history(
    ip_address: str,
    limit: int = Query(default=20, ge=1, le=100),
):
    """
    Retrieve historical intelligence assessments for an IP address.
    """

    try:
        request = IPAddressRequest(ip_address=ip_address)

        history = intelligence_repository.get_assessments_by_ip(
            request.ip_address,
            limit=limit,
        )

        return {
            "ip_address": request.ip_address,
            "count": len(history),
            "assessments": history,
        }

    except ValueError as error:
        raise HTTPException(
            status_code=422,
            detail="A valid IPv4 or IPv6 address is required",
        ) from error


@router.get("/assessments/{assessment_id}")
def get_assessment(assessment_id: int):
    """
    Retrieve a complete assessment, including provider results.
    """

    if assessment_id < 1:
        raise HTTPException(
            status_code=422,
            detail="assessment_id must be a positive integer",
        )

    assessment = intelligence_repository.get_assessment(
        assessment_id
    )

    if assessment is None:
        raise HTTPException(
            status_code=404,
            detail="Intelligence assessment not found",
        )

    return assessment
