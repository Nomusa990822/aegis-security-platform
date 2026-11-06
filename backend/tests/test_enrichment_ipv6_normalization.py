
import asyncio
from datetime import datetime, timezone

from app.intelligence.alert_enrichment import (
    AlertIntelligenceService,
    normalize_ip_address,
)
from app.intelligence.models import (
    EnrichmentStatus,
    IPClassification,
    IPIntelligenceAssessment,
)
from app.intelligence.repository import IntelligenceRepository


class CountingEnrichmentService:
    def __init__(self):
        self.calls = 0

    async def enrich_ip(self, source_ip):
        self.calls += 1

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


def test_equivalent_ipv6_formats_reuse_existing_assessment(
    isolated_database,
    seeded_alert,
):
    expanded_ip = "2606:4700:4700:0:0:0:0:1111"
    compressed_ip = "2606:4700:4700::1111"

    assert normalize_ip_address(expanded_ip) == (
        normalize_ip_address(compressed_ip)
    )

    repository = IntelligenceRepository()
    enrichment_service = CountingEnrichmentService()

    service = AlertIntelligenceService(
        enrichment_service=enrichment_service,
        repository=repository,
    )

    first_result = asyncio.run(
        service.enrich_alert(seeded_alert, expanded_ip)
    )

    second_result = asyncio.run(
        service.enrich_alert(seeded_alert, compressed_ip)
    )

    assert first_result["status"] == "completed"
    assert second_result["status"] == "already_enriched"

    assert enrichment_service.calls == 1

    assessment_id = (
        repository.get_assessment_by_alert_id(seeded_alert)
    )

    assert assessment_id == first_result["assessment_id"]

    assessment = repository.get_assessment(assessment_id)

    assert normalize_ip_address(
        assessment["ip_address"]
    ) == normalize_ip_address(compressed_ip)
