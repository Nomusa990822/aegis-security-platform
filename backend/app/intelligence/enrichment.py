from datetime import datetime, timezone
from ipaddress import ip_address, IPv4Address, IPv6Address

from app.intelligence.models import (
    EnrichmentStatus,
    IPClassification,
    IPIntelligenceAssessment,
    ProviderResult,
    ProviderStatus,
)
from app.intelligence.providers import AbuseIPDBProvider


def classify_ip(value: str) -> tuple[IPClassification, bool]:
    """
    Classify an IPv4 or IPv6 address.

    Returns:
        A tuple containing the classification and whether the address
        is globally routable.
    """
    address = ip_address(value)

    if address.is_unspecified:
        classification = IPClassification.UNSPECIFIED
    elif address.is_loopback:
        classification = IPClassification.LOOPBACK
    elif address.is_link_local:
        classification = IPClassification.LINK_LOCAL
    elif address.is_multicast:
        classification = IPClassification.MULTICAST
    elif address.is_private:
        classification = IPClassification.PRIVATE
    elif address.is_reserved:
        classification = IPClassification.RESERVED
    else:
        classification = IPClassification.PUBLIC

    return classification, address.is_global


class ThreatIntelligenceEnrichmentService:
    """
    Coordinates IP classification and external threat-intelligence lookups.
    """

    def __init__(
        self,
        providers: list | None = None,
    ):
        self.providers = providers if providers is not None else [
            AbuseIPDBProvider()
        ]

    async def enrich_ip(self, value: str) -> IPIntelligenceAssessment:
        address = ip_address(value.strip())
        normalized_ip = str(address)

        classification, is_global = classify_ip(normalized_ip)
        assessed_at = datetime.now(timezone.utc)

        # Non-global addresses are classified locally. They are not
        # submitted to external reputation providers.
        if not is_global:
            return IPIntelligenceAssessment(
                ip_address=normalized_ip,
                classification=classification,
                is_global=False,
                enrichment_status=EnrichmentStatus.SKIPPED,
                threat_score=0,
                confidence=1.0,
                reputation="not_applicable",
                categories=["non_global_address"],
                assessed_at=assessed_at,
            )

        provider_results: list[ProviderResult] = []

        for provider in self.providers:
            try:
                result = await provider.check_ip(normalized_ip)

                if not isinstance(result, ProviderResult):
                    raise TypeError(
                        "Provider must return a ProviderResult instance"
                    )

                provider_results.append(result)

            except Exception as exc:
                provider_results.append(
                    ProviderResult(
                        provider=getattr(
                            provider,
                            "PROVIDER_NAME",
                            provider.__class__.__name__,
                        ),
                        status=ProviderStatus.ERROR,
                        error=f"Provider execution failed: {type(exc).__name__}.",
                    )
                )

        successful_results = [
            result
            for result in provider_results
            if result.status == ProviderStatus.SUCCESS
        ]

        if not provider_results:
            status = EnrichmentStatus.SKIPPED
        elif len(successful_results) == len(provider_results):
            status = EnrichmentStatus.COMPLETED
        elif successful_results:
            status = EnrichmentStatus.PARTIAL
        else:
            status = EnrichmentStatus.FAILED

        # Only successful provider results contribute to the assessment.
        # Failed and unavailable providers never imply a clean reputation.
        threat_score = self._calculate_threat_score(successful_results)

        confidence = (
            sum(result.confidence for result in successful_results)
            / len(successful_results)
            if successful_results
            else 0.0
        )

        categories = sorted({
            category
            for result in successful_results
            for category in result.categories
        })

        reputation = self._determine_reputation(
            successful_results,
            threat_score,
        )

        return IPIntelligenceAssessment(
            ip_address=normalized_ip,
            classification=classification,
            is_global=True,
            enrichment_status=status,
            threat_score=threat_score,
            confidence=confidence,
            reputation=reputation,
            categories=categories,
            provider_results=provider_results,
            assessed_at=assessed_at,
        )

    @staticmethod
    def _calculate_threat_score(
        results: list[ProviderResult],
    ) -> int:
        """
        Calculate a preliminary score from successful provider results.

        This initial implementation uses the strongest provider score.
        It avoids treating multiple reports from one provider as
        independent evidence.
        """
        if not results:
            return 0

        scores = []

        for result in results:
            if result.provider == "abuseipdb":
                raw_score = result.details.get(
                    "abuse_confidence_score"
                )

                if isinstance(raw_score, (int, float)):
                    scores.append(
                        max(0, min(100, int(raw_score)))
                    )

        return max(scores, default=0)

    @staticmethod
    def _determine_reputation(
        results: list[ProviderResult],
        threat_score: int,
    ) -> str:
        if not results:
            return "unknown"

        if threat_score >= 75:
            return "malicious"

        if threat_score >= 25:
            return "suspicious"

        # A low score is meaningful only when a provider successfully
        # returned an assessment.
        return "low_risk"
