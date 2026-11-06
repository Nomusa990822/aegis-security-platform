
import asyncio
from datetime import datetime, timezone

from app.intelligence.alert_enrichment import AlertIntelligenceService
from app.intelligence.models import (
    EnrichmentStatus,
    IPClassification,
    IPIntelligenceAssessment,
)
from app.intelligence.repository import IntelligenceRepository


class LifecycleEnrichmentService:
    def __init__(self):
        self.calls = 0

    async def enrich_ip(self, source_ip):
        self.calls += 1

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


def test_lock_registry_is_cleaned_after_concurrent_requests(
    isolated_database,
    seeded_alert,
):
    repository = IntelligenceRepository()
    enrichment_service = LifecycleEnrichmentService()

    service = AlertIntelligenceService(
        enrichment_service=enrichment_service,
        repository=repository,
    )

    async def run_requests():
        results = await asyncio.gather(
            *[
                service.enrich_alert(seeded_alert, "8.8.8.8")
                for _ in range(10)
            ]
        )

        return results

    results = asyncio.run(run_requests())

    assert len(results) == 10

    assert sum(
        result["status"] == "completed"
        for result in results
    ) == 1

    assert sum(
        result["status"] == "already_enriched"
        for result in results
    ) == 9

    assert enrichment_service.calls == 1

    assert service._alert_locks == {}


def test_lock_registry_is_cleaned_after_sequential_requests(
    isolated_database,
    seeded_alert,
):
    service = AlertIntelligenceService(
        enrichment_service=LifecycleEnrichmentService(),
        repository=IntelligenceRepository(),
    )

    first_result = asyncio.run(
        service.enrich_alert(seeded_alert, "8.8.8.8")
    )

    assert first_result["status"] == "completed"
    assert service._alert_locks == {}

    second_result = asyncio.run(
        service.enrich_alert(seeded_alert, "8.8.8.8")
    )

    assert second_result["status"] == "already_enriched"
    assert service._alert_locks == {}


def test_lock_registry_is_cleaned_after_empty_source_ip(
    isolated_database,
    seeded_alert,
):
    service = AlertIntelligenceService(
        repository=IntelligenceRepository(),
    )

    result = asyncio.run(
        service.enrich_alert(seeded_alert, "")
    )

    assert result["status"] == "skipped"
    assert service._alert_locks == {}
