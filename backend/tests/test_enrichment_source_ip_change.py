
from datetime import datetime, timezone
import asyncio

from app.intelligence.alert_enrichment import AlertIntelligenceService
from app.intelligence.models import (
    EnrichmentStatus,
    IPClassification,
    IPIntelligenceAssessment,
)
from app.intelligence.repository import IntelligenceRepository


class IPTrackingEnrichmentService:
    def __init__(self):
        self.calls = []

    async def enrich_ip(self, source_ip):
        self.calls.append(source_ip)

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


def test_changed_source_ip_gets_a_new_assessment(
    isolated_database,
    seeded_alert,
):
    repository = IntelligenceRepository()
    enrichment_service = IPTrackingEnrichmentService()

    service = AlertIntelligenceService(
        enrichment_service=enrichment_service,
        repository=repository,
    )

    first_result = asyncio.run(
        service.enrich_alert(seeded_alert, "8.8.8.8")
    )

    second_result = asyncio.run(
        service.enrich_alert(seeded_alert, "1.1.1.1")
    )

    assert first_result["status"] == "completed"
    assert second_result["status"] == "completed"

    assert first_result["assessment_id"] == 1
    assert second_result["assessment_id"] == 2

    assert enrichment_service.calls == [
        "8.8.8.8",
        "1.1.1.1",
    ]

    first_assessment = repository.get_assessment(1)
    second_assessment = repository.get_assessment(2)

    assert first_assessment["ip_address"] == "8.8.8.8"
    assert second_assessment["ip_address"] == "1.1.1.1"

    assert repository.get_assessment_by_alert_id(
        seeded_alert
    ) == 2
