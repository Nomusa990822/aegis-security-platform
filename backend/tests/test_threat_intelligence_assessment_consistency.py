
import asyncio

from app.intelligence.enrichment import (
    ThreatIntelligenceEnrichmentService,
)
from app.intelligence.models import (
    EnrichmentStatus,
    ProviderResult,
    ProviderStatus,
)


class TestProvider:
    def __init__(self, name, result=None, error=None):
        self.PROVIDER_NAME = name
        self.result = result
        self.error = error

    async def check_ip(self, ip_address):
        if self.error:
            raise self.error

        return self.result


def provider_result(
    provider,
    score,
    confidence,
    categories,
):
    return ProviderResult(
        provider=provider,
        status=ProviderStatus.SUCCESS,
        reputation="suspicious",
        confidence=confidence,
        categories=categories,
        details={"abuse_confidence_score": score},
    )


def test_multiple_successful_providers_produce_consistent_assessment():
    service = ThreatIntelligenceEnrichmentService(
        providers=[
            TestProvider(
                "abuseipdb",
                provider_result(
                    "abuseipdb",
                    85,
                    0.9,
                    ["brute_force"],
                ),
            ),
            TestProvider(
                "secondary_provider",
                provider_result(
                    "secondary_provider",
                    40,
                    0.7,
                    ["port_scanning"],
                ),
            ),
        ]
    )

    assessment = asyncio.run(service.enrich_ip("8.8.8.8"))

    assert assessment.enrichment_status == EnrichmentStatus.COMPLETED
    assert assessment.threat_score == 85
    assert assessment.confidence == 0.8
    assert assessment.reputation == "malicious"

    assert assessment.categories == [
        "brute_force",
        "port_scanning",
    ]

    assert len(assessment.provider_results) == 2


def test_failed_provider_does_not_contaminate_partial_assessment():
    service = ThreatIntelligenceEnrichmentService(
        providers=[
            TestProvider(
                "abuseipdb",
                provider_result(
                    "abuseipdb",
                    80,
                    0.9,
                    ["malicious_activity"],
                ),
            ),
            TestProvider(
                "failing_provider",
                error=RuntimeError("Provider unavailable"),
            ),
        ]
    )

    assessment = asyncio.run(service.enrich_ip("1.1.1.1"))

    assert assessment.enrichment_status == EnrichmentStatus.PARTIAL
    assert assessment.threat_score == 80
    assert assessment.confidence == 0.9
    assert assessment.reputation == "malicious"

    assert assessment.categories == ["malicious_activity"]

    assert assessment.provider_results[0].status == ProviderStatus.SUCCESS
    assert assessment.provider_results[1].status == ProviderStatus.ERROR


def test_all_failed_providers_produce_consistent_failed_assessment():
    service = ThreatIntelligenceEnrichmentService(
        providers=[
            TestProvider(
                "provider_one",
                error=RuntimeError("First provider failed"),
            ),
            TestProvider(
                "provider_two",
                error=RuntimeError("Second provider failed"),
            ),
        ]
    )

    assessment = asyncio.run(service.enrich_ip("8.8.4.4"))

    assert assessment.enrichment_status == EnrichmentStatus.FAILED
    assert assessment.threat_score == 0
    assert assessment.confidence == 0.0
    assert assessment.reputation == "unknown"
    assert assessment.categories == []

    assert all(
        result.status == ProviderStatus.ERROR
        for result in assessment.provider_results
    )


def test_non_global_ip_is_classified_without_external_provider_calls():
    provider = TestProvider(
        "must_not_run",
        error=RuntimeError("External lookup should not happen"),
    )

    service = ThreatIntelligenceEnrichmentService(
        providers=[provider]
    )

    assessment = asyncio.run(service.enrich_ip("192.168.1.10"))

    assert assessment.enrichment_status == EnrichmentStatus.SKIPPED
    assert assessment.is_global is False
    assert assessment.threat_score == 0
    assert assessment.confidence == 1.0
    assert assessment.reputation == "not_applicable"
    assert assessment.provider_results == []
