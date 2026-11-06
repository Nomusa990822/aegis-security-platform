import asyncio
from datetime import datetime, timezone

from app.intelligence.alert_enrichment import AlertIntelligenceService
from app.intelligence.models import (
    EnrichmentStatus,
    IPClassification,
    IPIntelligenceAssessment,
)
from app.intelligence.repository import IntelligenceRepository


class ConcurrentEnrichmentService:
    def __init__(self):
        self.calls = []

    async def enrich_ip(self, source_ip):
        self.calls.append(source_ip)

        # Give the second concurrent request an opportunity
        # to attempt enrichment while the first is running.
        await asyncio.sleep(0.05)

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


def test_concurrent_enrichment_does_not_duplicate_assessments(
    isolated_database,
    seeded_alert,
):
    repository = IntelligenceRepository()
    enrichment_service = ConcurrentEnrichmentService()

    service = AlertIntelligenceService(
        enrichment_service=enrichment_service,
        repository=repository,
    )

    async def run_concurrent_requests():
        return await asyncio.gather(
            service.enrich_alert(seeded_alert, "8.8.8.8"),
            service.enrich_alert(seeded_alert, "8.8.8.8"),
        )

    results = asyncio.run(run_concurrent_requests())

    assert len(results) == 2

    statuses = sorted(
        result["status"]
        for result in results
    )

    assert statuses == [
        "already_enriched",
        "completed",
    ]

    assert len(enrichment_service.calls) == 1

    history = repository.get_assessments_by_ip("8.8.8.8")

    assert len(history) == 1

    assert repository.get_assessment_by_alert_id(
        seeded_alert
    ) == history[0]["id"]
