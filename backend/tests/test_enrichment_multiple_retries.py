
from datetime import datetime, timezone
import asyncio

from app.intelligence.alert_enrichment import AlertIntelligenceService
from app.intelligence.models import (
    EnrichmentStatus,
    IPClassification,
    IPIntelligenceAssessment,
)
from app.intelligence.repository import IntelligenceRepository


class MultipleFailureEnrichmentService:
    def __init__(self):
        self.calls = 0
        self.statuses = [
            EnrichmentStatus.FAILED,
            EnrichmentStatus.FAILED,
            EnrichmentStatus.COMPLETED,
        ]

    async def enrich_ip(self, source_ip):
        status = self.statuses[self.calls]
        self.calls += 1

        return IPIntelligenceAssessment(
            ip_address=source_ip,
            classification=IPClassification.PUBLIC,
            is_global=True,
            enrichment_status=status,
            threat_score=15 if status == EnrichmentStatus.COMPLETED else 0,
            confidence=0.9 if status == EnrichmentStatus.COMPLETED else 0.0,
            reputation="low" if status == EnrichmentStatus.COMPLETED else "unknown",
            assessed_at=datetime.now(timezone.utc),
        )


def test_multiple_failed_attempts_can_eventually_succeed(
    isolated_database,
    seeded_alert,
):
    repository = IntelligenceRepository()
    enrichment_service = MultipleFailureEnrichmentService()

    service = AlertIntelligenceService(
        enrichment_service=enrichment_service,
        repository=repository,
    )

    first_result = asyncio.run(
        service.enrich_alert(seeded_alert, "8.8.8.8")
    )

    second_result = asyncio.run(
        service.enrich_alert(seeded_alert, "8.8.8.8")
    )

    third_result = asyncio.run(
        service.enrich_alert(seeded_alert, "8.8.8.8")
    )

    assert first_result["status"] == "failed"
    assert second_result["status"] == "failed"
    assert third_result["status"] == "completed"

    assert enrichment_service.calls == 3

    assert first_result["assessment_id"] == 1
    assert second_result["assessment_id"] == 2
    assert third_result["assessment_id"] == 3

    history = repository.get_assessments_by_ip("8.8.8.8")

    assert len(history) == 3

    assert {
        item["enrichment_status"] for item in history
    } == {"failed", "completed"}

    assert repository.get_assessment_by_alert_id(
        seeded_alert
    ) == 3
