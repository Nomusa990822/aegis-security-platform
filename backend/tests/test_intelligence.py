
import asyncio

import pytest

from app.intelligence.enrichment import (
    ThreatIntelligenceEnrichmentService,
    classify_ip,
)
from app.intelligence.models import (
    EnrichmentStatus,
    IPClassification,
    ProviderResult,
    ProviderStatus,
)


class MockProvider:
    PROVIDER_NAME = "mock_provider"

    def __init__(self, result=None):
        self.result = result
        self.calls = []

    async def check_ip(self, ip_address):
        self.calls.append(ip_address)

        if isinstance(self.result, Exception):
            raise self.result

        return self.result


def test_classify_public_ipv4():
    classification, eligible = classify_ip("8.8.8.8")

    assert classification == IPClassification.PUBLIC
    assert eligible is True


def test_classify_public_ipv6():
    classification, eligible = classify_ip("2001:4860:4860::8888")

    assert classification == IPClassification.PUBLIC
    assert eligible is True


@pytest.mark.parametrize(
    ("ip_address", "expected_classification"),
    [
        ("192.168.1.10", IPClassification.PRIVATE),
        ("127.0.0.1", IPClassification.LOOPBACK),
        ("169.254.1.1", IPClassification.LINK_LOCAL),
        ("224.0.0.1", IPClassification.MULTICAST),
        ("0.0.0.0", IPClassification.UNSPECIFIED),
        ("192.0.2.10", IPClassification.DOCUMENTATION),
        ("198.51.100.10", IPClassification.DOCUMENTATION),
        ("203.0.113.10", IPClassification.DOCUMENTATION),
        ("2001:db8::1", IPClassification.DOCUMENTATION),
        ("::1", IPClassification.LOOPBACK),
    ],
)
def test_non_public_addresses_are_not_eligible(
    ip_address,
    expected_classification,
):
    classification, eligible = classify_ip(ip_address)

    assert classification == expected_classification
    assert eligible is False


def test_non_global_ip_skips_provider_lookup():
    provider = MockProvider()

    service = ThreatIntelligenceEnrichmentService(
        providers=[provider]
    )

    assessment = asyncio.run(
        service.enrich_ip("192.168.1.10")
    )

    assert assessment.classification == IPClassification.PRIVATE
    assert assessment.enrichment_status == EnrichmentStatus.SKIPPED
    assert assessment.reputation == "not_applicable"
    assert provider.calls == []


def test_public_ip_with_unavailable_provider_is_unknown():
    provider = MockProvider(
        ProviderResult(
            provider="mock_provider",
            status=ProviderStatus.UNAVAILABLE,
            error="Provider unavailable",
        )
    )

    service = ThreatIntelligenceEnrichmentService(
        providers=[provider]
    )

    assessment = asyncio.run(
        service.enrich_ip("8.8.8.8")
    )

    assert assessment.enrichment_status == EnrichmentStatus.FAILED
    assert assessment.reputation == "unknown"
    assert assessment.threat_score == 0
    assert assessment.confidence == 0.0
    assert provider.calls == ["8.8.8.8"]


def test_public_ip_with_successful_provider():
    provider = MockProvider(
        ProviderResult(
            provider="mock_provider",
            status=ProviderStatus.SUCCESS,
            reputation="suspicious",
            confidence=0.85,
            categories=["brute_force"],
            details={"source": "test"},
        )
    )

    service = ThreatIntelligenceEnrichmentService(
        providers=[provider]
    )

    assessment = asyncio.run(
        service.enrich_ip("8.8.8.8")
    )

    assert assessment.enrichment_status == EnrichmentStatus.COMPLETED
    assert assessment.reputation == "low_risk"
    assert assessment.confidence == 0.85
    assert assessment.categories == ["brute_force"]
    assert provider.calls == ["8.8.8.8"]


def test_provider_exception_does_not_crash_enrichment():
    provider = MockProvider(
        RuntimeError("Simulated provider failure")
    )

    service = ThreatIntelligenceEnrichmentService(
        providers=[provider]
    )

    assessment = asyncio.run(
        service.enrich_ip("8.8.8.8")
    )

    assert assessment.enrichment_status == EnrichmentStatus.FAILED
    assert assessment.reputation == "unknown"
    assert len(assessment.provider_results) == 1
    assert assessment.provider_results[0].status == ProviderStatus.ERROR



def test_provider_timeout_becomes_unavailable_without_crashing_enrichment():
    class SlowProvider:
        PROVIDER_NAME = "slow_provider"

        async def check_ip(self, ip_address):
            await asyncio.sleep(0.05)
            return ProviderResult(
                provider=self.PROVIDER_NAME,
                status=ProviderStatus.SUCCESS,
                reputation="malicious",
                confidence=1.0,
            )

    service = ThreatIntelligenceEnrichmentService(
        providers=[SlowProvider()],
        provider_timeout=0.005,
    )

    assessment = asyncio.run(service.enrich_ip("8.8.8.8"))

    assert assessment.enrichment_status == EnrichmentStatus.FAILED
    assert assessment.reputation == "unknown"
    assert assessment.threat_score == 0
    assert len(assessment.provider_results) == 1
    assert assessment.provider_results[0].provider == "slow_provider"
    assert assessment.provider_results[0].status == ProviderStatus.UNAVAILABLE
    assert "configured 0.005-second timeout" in assessment.provider_results[0].error


def test_timed_out_provider_does_not_discard_successful_provider_result():
    class SlowProvider:
        PROVIDER_NAME = "slow_provider"

        async def check_ip(self, ip_address):
            await asyncio.sleep(0.05)
            return ProviderResult(
                provider=self.PROVIDER_NAME,
                status=ProviderStatus.SUCCESS,
                reputation="malicious",
                confidence=1.0,
                categories=["late_result"],
            )

    successful_provider = MockProvider(
        ProviderResult(
            provider="healthy_provider",
            status=ProviderStatus.SUCCESS,
            reputation="suspicious",
            confidence=0.8,
            categories=["brute_force"],
        )
    )
    service = ThreatIntelligenceEnrichmentService(
        providers=[SlowProvider(), successful_provider],
        provider_timeout=0.005,
    )

    assessment = asyncio.run(service.enrich_ip("8.8.8.8"))

    assert assessment.enrichment_status == EnrichmentStatus.PARTIAL
    assert assessment.reputation != "unknown"
    assert len(assessment.provider_results) == 2
    assert assessment.provider_results[0].status == ProviderStatus.UNAVAILABLE
    assert assessment.provider_results[1].status == ProviderStatus.SUCCESS
    assert assessment.categories == ["brute_force"]
    assert successful_provider.calls == ["8.8.8.8"]


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan"), True])
def test_provider_timeout_configuration_must_be_finite_and_positive(timeout):
    with pytest.raises(ValueError, match="finite positive"):
        ThreatIntelligenceEnrichmentService(provider_timeout=timeout)
