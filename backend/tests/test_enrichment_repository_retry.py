
from datetime import datetime, timezone
import asyncio

from app.intelligence.alert_enrichment import AlertIntelligenceService
from app.intelligence.models import (
    EnrichmentStatus,
    IPClassification,
    IPIntelligenceAssessment,
)
from app.intelligence.repository import IntelligenceRepository


class SequentialEnrichmentService:
    def __init__(self, statuses):
        self.statuses = statuses
        self.calls = 0

    async def enrich_ip(self, source_ip):
        status = self.statuses[self.calls]
        self.calls += 1

        return IPIntelligenceAssessment(
            ip_address=source_ip,
            classification=IPClassification.PUBLIC,
            is_global=True,
            enrichment_status=status,
            threat_score=10 if status == EnrichmentStatus.COMPLETED else 0,
            confidence=0.9 if status == EnrichmentStatus.COMPLETED else 0.0,
            reputation="low" if status == EnrichmentStatus.COMPLETED else "unknown",
            assessed_at=datetime.now(timezone.utc),
        )


def test_failed_assessment_is_preserved_after_successful_retry(
    isolated_database,
    seeded_alert,
):
    repository = IntelligenceRepository()

    enrichment_service = SequentialEnrichmentService(
        [
            EnrichmentStatus.FAILED,
            EnrichmentStatus.COMPLETED,
        ]
    )

    service = AlertIntelligenceService(
        enrichment_service=enrichment_service,
        repository=repository,
    )

    first_result = asyncio.run(
        service.enrich_alert(seeded_alert, "8.8.8.8")
    )

    assert first_result["status"] == "failed"
    assert first_result["assessment_id"] == 1

    second_result = asyncio.run(
        service.enrich_alert(seeded_alert, "8.8.8.8")
    )

    assert second_result["status"] == "completed"
    assert second_result["assessment_id"] == 2
    assert enrichment_service.calls == 2

    first_assessment = repository.get_assessment(1)
    second_assessment = repository.get_assessment(2)

    assert first_assessment["enrichment_status"] == "failed"
    assert second_assessment["enrichment_status"] == "completed"

    latest_id = repository.get_assessment_by_alert_id(
        seeded_alert
    )

    assert latest_id == 2

    history = repository.get_assessments_by_ip("8.8.8.8")

    assert len(history) == 2
    assert {item["enrichment_status"] for item in history} == {
        "failed",
        "completed",
    }


def test_completed_assessment_is_reused_from_sqlite(
    isolated_database,
    seeded_alert,
):
    repository = IntelligenceRepository()

    enrichment_service = SequentialEnrichmentService(
        [
            EnrichmentStatus.COMPLETED,
            EnrichmentStatus.FAILED,
        ]
    )

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

    assert first_result["status"] == "completed"
    assert second_result["status"] == "already_enriched"

    assert enrichment_service.calls == 1
    assert repository.get_assessment_by_alert_id(seeded_alert) == 1
