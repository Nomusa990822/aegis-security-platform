
import asyncio

import httpx

from app.intelligence.models import ProviderStatus
from app.intelligence.providers import AbuseIPDBProvider


class TimeoutAsyncClient:
    received_timeout = None

    def __init__(self, timeout):
        type(self).received_timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return False

    async def get(self, *args, **kwargs):
        raise httpx.ReadTimeout("Simulated provider timeout")


def test_abuseipdb_timeout_returns_unavailable_status(monkeypatch):
    monkeypatch.setattr(
        "app.intelligence.providers.httpx.AsyncClient",
        TimeoutAsyncClient,
    )

    provider = AbuseIPDBProvider(
        api_key="test-api-key",
        timeout=2.5,
    )

    result = asyncio.run(
        provider.check_ip("8.8.8.8")
    )

    assert result.status == ProviderStatus.UNAVAILABLE

    assert result.error == "AbuseIPDB request timed out."

    assert TimeoutAsyncClient.received_timeout == 2.5


def test_abuseipdb_uses_default_timeout(monkeypatch):
    monkeypatch.setattr(
        "app.intelligence.providers.httpx.AsyncClient",
        TimeoutAsyncClient,
    )

    provider = AbuseIPDBProvider(
        api_key="test-api-key",
    )

    result = asyncio.run(
        provider.check_ip("1.1.1.1")
    )

    assert result.status == ProviderStatus.UNAVAILABLE

    assert TimeoutAsyncClient.received_timeout == 10.0
