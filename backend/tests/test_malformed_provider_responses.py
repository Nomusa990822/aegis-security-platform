
import asyncio

import pytest

from app.intelligence.enrichment import (
    ThreatIntelligenceEnrichmentService,
)
from app.intelligence.models import (
    EnrichmentStatus,
    ProviderStatus,
)


class MalformedProvider:
    PROVIDER_NAME = "malformed_provider"

    def __init__(self, response):
        self.response = response

    async def check_ip(self, ip_address):
        return self.response


class ValidProvider:
    PROVIDER_NAME = "valid_provider"

    async def check_ip(self, ip_address):
        from app.intelligence.models import ProviderResult

        return ProviderResult(
            provider=self.PROVIDER_NAME,
            status=ProviderStatus.SUCCESS,
            reputation="low_risk",
            confidence=0.8,
            categories=["reconnaissance"],
        )


@pytest.mark.parametrize(
    "malformed_response",
    [
        None,
        {},
        "invalid response",
        [],
        123,
    ],
)
def test_malformed_provider_response_does_not_crash_enrichment(
    malformed_response,
):
    service = ThreatIntelligenceEnrichmentService(
        providers=[
            MalformedProvider(malformed_response),
            ValidProvider(),
        ]
    )

    assessment = asyncio.run(
        service.enrich_ip("8.8.8.8")
    )

    assert assessment.enrichment_status == EnrichmentStatus.PARTIAL

    assert len(assessment.provider_results) == 2

    malformed_result = assessment.provider_results[0]

    assert malformed_result.status == ProviderStatus.ERROR

    assert "TypeError" in malformed_result.error

    assert assessment.provider_results[1].status == ProviderStatus.SUCCESS

    assert assessment.categories == ["reconnaissance"]


def test_malformed_responses_from_all_providers_produce_failed_assessment():
    service = ThreatIntelligenceEnrichmentService(
        providers=[
            MalformedProvider(None),
            MalformedProvider({"unexpected": "payload"}),
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
