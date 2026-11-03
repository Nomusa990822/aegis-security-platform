import os
from datetime import datetime, timezone
from typing import Any

import httpx

from app.intelligence.models import ProviderResult, ProviderStatus


class AbuseIPDBProvider:
    """
    Retrieves IP reputation information from AbuseIPDB.

    The API key is read from the ABUSEIPDB_API_KEY environment variable.
    """

    BASE_URL = "https://api.abuseipdb.com/api/v2/check"
    PROVIDER_NAME = "abuseipdb"

    def __init__(self, api_key: str | None = None, timeout: float = 10.0):
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
        self.timeout = timeout

    async def check_ip(self, ip_address: str) -> ProviderResult:
        if not self.api_key:
            return ProviderResult(
                provider=self.PROVIDER_NAME,
                status=ProviderStatus.UNAVAILABLE,
                error="AbuseIPDB API key is not configured.",
                checked_at=datetime.now(timezone.utc),
            )

        headers = {
            "Accept": "application/json",
            "Key": self.api_key,
        }

        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90,
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    self.BASE_URL,
                    headers=headers,
                    params=params,
                )

            if response.status_code == 429:
                return ProviderResult(
                    provider=self.PROVIDER_NAME,
                    status=ProviderStatus.RATE_LIMITED,
                    error="AbuseIPDB rate limit reached.",
                )

            if response.status_code == 404:
                return ProviderResult(
                    provider=self.PROVIDER_NAME,
                    status=ProviderStatus.NOT_FOUND,
                    error="No intelligence record was found.",
                )

            response.raise_for_status()
            payload: dict[str, Any] = response.json()
            data = payload.get("data", {})

            abuse_score = int(data.get("abuseConfidenceScore", 0))
            total_reports = int(data.get("totalReports", 0))

            if abuse_score >= 75:
                reputation = "malicious"
            elif abuse_score >= 25:
                reputation = "suspicious"
            else:
                reputation = "low_risk"

            categories = sorted({
                str(category)
                for report in data.get("reports", [])
                for category in report.get("categories", [])
            })

            return ProviderResult(
                provider=self.PROVIDER_NAME,
                status=ProviderStatus.SUCCESS,
                reputation=reputation,
                confidence=abuse_score / 100,
                categories=categories,
                details={
                    "abuse_confidence_score": abuse_score,
                    "total_reports": total_reports,
                    "num_distinct_users": data.get("numDistinctUsers", 0),
                    "country_code": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "is_tor": data.get("isTor", False),
                    "last_reported_at": data.get("lastReportedAt"),
                },
            )

        except httpx.TimeoutException:
            return ProviderResult(
                provider=self.PROVIDER_NAME,
                status=ProviderStatus.UNAVAILABLE,
                error="AbuseIPDB request timed out.",
            )

        except httpx.HTTPStatusError as exc:
            return ProviderResult(
                provider=self.PROVIDER_NAME,
                status=ProviderStatus.ERROR,
                error=f"AbuseIPDB returned HTTP {exc.response.status_code}.",
            )

        except (httpx.RequestError, ValueError, TypeError) as exc:
            return ProviderResult(
                provider=self.PROVIDER_NAME,
                status=ProviderStatus.ERROR,
                error=f"AbuseIPDB lookup failed: {type(exc).__name__}.",
            )
