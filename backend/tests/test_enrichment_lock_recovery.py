
import asyncio
from datetime import datetime, timezone

from app.intelligence.alert_enrichment import AlertIntelligenceService
from app.intelligence.models import (
    EnrichmentStatus,
    IPClassification,
    IPIntelligenceAssessment,
)
from app.intelligence.repository import IntelligenceRepository


class FailOnceEnrichmentService:
    def __init__(self):
        self.calls = 0

    async def enrich_ip(self, source_ip):
        self.calls += 1

        if self.calls == 1:
            raise RuntimeError("Simulated provider outage")

        return IPIntelligenceAssessment(
            ip_address=source_ip,
            classification=IPClassification.PUBLIC,
            is_global=True,
            enrichment_status=EnrichmentStatus.COMPLETED,
            threat_score=10,
            confidence=0.9,
            reputation="low",
            assessed_at=datetime.now(timezone.utc),
        )


def test_lock_is_released_after_provider_failure(
    isolated_database,
    seeded_alert,
):
    repository = IntelligenceRepository()
    enrichment_service = FailOnceEnrichmentService()

    service = AlertIntelligenceService(
        enrichment_service=enrichment_service,
        repository=repository,
    )

    async def run_requests():
        return await asyncio.gather(
            service.enrich_alert(seeded_alert, "8.8.8.8"),
            service.enrich_alert(seeded_alert, "8.8.8.8"),
        )

    results = asyncio.run(run_requests())

    statuses = sorted(
        result["status"]
        for result in results
    )

    assert statuses == ["completed", "error"]

    assert enrichment_service.calls == 2

    assessment_id = (
        repository.get_assessment_by_alert_id(seeded_alert)
    )

    assert assessment_id is not None

    assessment = repository.get_assessment(assessment_id)

    assert assessment["ip_address"] == "8.8.8.8"
    assert assessment["enrichment_status"] == "completed"

    # A subsequent request must reuse the successful assessment.
    retry_result = asyncio.run(
        service.enrich_alert(seeded_alert, "8.8.8.8")
    )

    assert retry_result["status"] == "already_enriched"
    assert enrichment_service.calls == 2
