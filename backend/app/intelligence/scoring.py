from app.intelligence.models import ProviderResult, ProviderStatus


class ThreatScoringEngine:
    """
    Calculates a normalised threat score from successful
    intelligence-provider assessments.

    Scores range from 0 to 100.
    """

    def calculate_score(
        self,
        results: list[ProviderResult],
    ) -> int:
        successful_results = [
            result
            for result in results
            if result.status == ProviderStatus.SUCCESS
        ]

        if not successful_results:
            return 0

        provider_scores = []

        for result in successful_results:
            score = self._extract_provider_score(result)

            if score is not None:
                provider_scores.append(score)

        if not provider_scores:
            return 0

        # Use the strongest available provider score.
        # This avoids falsely treating multiple reports from the
        # same intelligence source as independent confirmation.
        return max(provider_scores)

    @staticmethod
    def _extract_provider_score(
        result: ProviderResult,
    ) -> int | None:
        if result.provider == "abuseipdb":
            value = result.details.get("abuse_confidence_score")

            if isinstance(value, (int, float)):
                return max(0, min(100, round(value)))

        return None

    @staticmethod
    def determine_reputation(score: int, has_successful_results: bool) -> str:
        if not has_successful_results:
            return "unknown"

        if score >= 75:
            return "malicious"

        if score >= 25:
            return "suspicious"

        return "low_risk"

    @staticmethod
    def calculate_confidence(
        results: list[ProviderResult],
    ) -> float:
        successful_results = [
            result
            for result in results
            if result.status == ProviderStatus.SUCCESS
        ]

        if not successful_results:
            return 0.0

        return round(
            sum(result.confidence for result in successful_results)
            / len(successful_results),
            4,
        )
