import logging

from app.intelligence.enrichment import (
    ThreatIntelligenceEnrichmentService,
)
from app.intelligence.repository import IntelligenceRepository


logger = logging.getLogger(__name__)


class AlertIntelligenceService:
    """
    Automatically enrich security alerts with IP intelligence.

    Existing assessments are reused to prevent duplicate lookups.
    """

    def __init__(
        self,
        enrichment_service=None,
        repository=None,
    ):
        self.enrichment_service = (
            enrichment_service
            or ThreatIntelligenceEnrichmentService()
        )

        self.repository = (
            repository
            or IntelligenceRepository()
        )

    async def enrich_alert(
        self,
        alert_id: int,
        source_ip: str,
    ) -> dict:
        """
        Enrich an alert's source IP and persist its assessment.

        Returns a structured result without allowing an
        intelligence-provider failure to invalidate an alert.
        """

        if not source_ip:
            return {
                "status": "skipped",
                "alert_id": alert_id,
                "assessment_id": None,
                "message": "Alert has no source IP.",
            }

        try:
            existing_id = (
                self.repository.get_assessment_by_alert_id(
                    alert_id
                )
            )

            if existing_id is not None:
                return {
                    "status": "already_enriched",
                    "alert_id": alert_id,
                    "assessment_id": existing_id,
                    "message": "An intelligence assessment already exists.",
                }

            assessment = (
                await self.enrichment_service.enrich_ip(
                    source_ip
                )
            )

            assessment_id = (
                self.repository.save_assessment(
                    assessment,
                    alert_id=alert_id,
                )
            )

            return {
                "status": assessment.enrichment_status,
                "alert_id": alert_id,
                "assessment_id": assessment_id,
                "threat_score": assessment.threat_score,
                "reputation": assessment.reputation,
                "message": "Alert intelligence assessment saved.",
            }

        except Exception:
            logger.exception(
                "Automatic intelligence enrichment failed for alert %s",
                alert_id,
            )

            return {
                "status": "error",
                "alert_id": alert_id,
                "assessment_id": None,
                "message": "Intelligence enrichment could not be completed.",
            }
