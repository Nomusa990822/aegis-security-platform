
import asyncio

from app.intelligence.enrichment import (
    ThreatIntelligenceEnrichmentService,
)
from app.intelligence.models import (
    EnrichmentStatus,
    ProviderResult,
    ProviderStatus,
)


class FailingProvider:
    PROVIDER_NAME = "failing_provider"

    async def check_ip(self, ip_address):
        raise RuntimeError("Simulated provider outage")


class SuccessfulProvider:
    PROVIDER_NAME = "successful_provider"

    async def check_ip(self, ip_address):
        return ProviderResult(
            provider=self.PROVIDER_NAME,
            status=ProviderStatus.SUCCESS,
            reputation="suspicious",
            confidence=0.85,
            categories=["port_scanning", "brute_force"],
            details={
                "source_ip": ip_address,
                "reports": 12,
            },
        )


def test_one_provider_failure_does_not_prevent_other_provider_success():
    service = ThreatIntelligenceEnrichmentService(
        providers=[
            FailingProvider(),
            SuccessfulProvider(),
        ]
    )

    assessment = asyncio.run(
        service.enrich_ip("8.8.8.8")
    )

    assert assessment.ip_address == "8.8.8.8"

    assert assessment.enrichment_status == EnrichmentStatus.PARTIAL

    assert len(assessment.provider_results) == 2

    failed_result = assessment.provider_results[0]
    successful_result = assessment.provider_results[1]

    assert failed_result.provider == "failing_provider"
    assert failed_result.status == ProviderStatus.ERROR
    assert "RuntimeError" in failed_result.error

    assert successful_result.provider == "successful_provider"
    assert successful_result.status == ProviderStatus.SUCCESS

    assert assessment.categories == [
        "brute_force",
        "port_scanning",
    ]

    assert assessment.confidence > 0

    assert assessment.reputation != "unknown"


def test_all_provider_failures_produce_failed_assessment():
    service = ThreatIntelligenceEnrichmentService(
        providers=[
            FailingProvider(),
            FailingProvider(),
        ]
    )

    assessment = asyncio.run(
        service.enrich_ip("1.1.1.1")
    )

    assert assessment.enrichment_status == EnrichmentStatus.FAILED

    assert len(assessment.provider_results) == 2

    assert all(
        result.status == ProviderStatus.ERROR
        for result in assessment.provider_results
    )

    assert assessment.categories == []
