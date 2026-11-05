
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network

from app.intelligence.models import (
    EnrichmentStatus,
    IPClassification,
    IPIntelligenceAssessment,
    ProviderResult,
    ProviderStatus,
)
from app.intelligence.providers import AbuseIPDBProvider
from app.intelligence.scoring import ThreatScoringEngine


def classify_ip(value: str) -> tuple[IPClassification, bool]:
    """
    Classify an IPv4 or IPv6 address.

    The boolean indicates whether the address is suitable
    for external public IP intelligence lookups.
    """

    address = ip_address(value)

    documentation_networks = (
        ip_network("192.0.2.0/24"),
        ip_network("198.51.100.0/24"),
        ip_network("203.0.113.0/24"),
        ip_network("2001:db8::/32"),
    )

    if any(
        address.version == network.version and address in network
        for network in documentation_networks
    ):
        classification = IPClassification.DOCUMENTATION

    elif address.is_unspecified:
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

    is_suitable_for_lookup = (
        classification == IPClassification.PUBLIC
        and address.is_global
    )

    return classification, is_suitable_for_lookup


class ThreatIntelligenceEnrichmentService:
    """
    Coordinates IP classification, external intelligence lookups,
    threat scoring and reputation assessment.
    """

    def __init__(
        self,
        providers: list | None = None,
        scoring_engine: ThreatScoringEngine | None = None,
    ):
        self.providers = (
            providers
            if providers is not None
            else [AbuseIPDBProvider()]
        )

        self.scoring_engine = (
            scoring_engine
            if scoring_engine is not None
            else ThreatScoringEngine()
        )

    async def enrich_ip(
        self,
        value: str,
    ) -> IPIntelligenceAssessment:
        address = ip_address(value.strip())
        normalized_ip = str(address)

        classification, is_global = classify_ip(normalized_ip)
        accessed_at = datetime.now(timezone.utc)

        # Non-global addresses are classified locally.
        # They are never submitted to external providers.
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
                accessed_at=accessed_at,
            )

        provider_results: list[ProviderResult] = []

        for provider in self.providers:
            try:
                # Use the common provider interface implemented by
                # AbuseIPDBProvider and the test MockProvider.
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
                        error=(
                            "Provider execution failed: "
                            f"{type(exc).__name__}."
                        ),
                    )
                )

        successful_results = [
            result
            for result in provider_results
            if result.status == ProviderStatus.SUCCESS
        ]

        # Determine the overall enrichment outcome.
        if not provider_results:
            status = EnrichmentStatus.SKIPPED

        elif not successful_results:
            status = EnrichmentStatus.FAILED

        elif len(successful_results) < len(provider_results):
            status = EnrichmentStatus.PARTIAL

        else:
            status = EnrichmentStatus.COMPLETED

        # Centralised threat scoring and confidence calculation.
        threat_score = self.scoring_engine.calculate_score(
            provider_results
        )

        confidence = self.scoring_engine.calculate_confidence(
            provider_results
        )

        reputation = self.scoring_engine.determine_reputation(
            threat_score,
            has_successful_results=bool(successful_results),
        )

        # Only successful provider results contribute categories.
        categories = sorted({
            category
            for result in successful_results
            for category in result.categories
        })

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
            accessed_at=accessed_at,
        )

    @staticmethod
    def _calculate_threat_score(
        results: list[ProviderResult],
    ) -> int:
        """Backwards-compatible scoring method."""

        return ThreatScoringEngine().calculate_score(results)

    @staticmethod
    def _determine_reputation(
        results: list[ProviderResult],
        threat_score: int,
    ) -> str:
        """Backwards-compatible reputation method."""

        has_successful_results = any(
            result.status == ProviderStatus.SUCCESS
            for result in results
        )

        return ThreatScoringEngine.determine_reputation(
            threat_score,
            has_successful_results,
        )
