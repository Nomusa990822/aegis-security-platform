import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.rate_limiting import APIRateLimitMiddleware


@pytest.fixture
def limited_client():
    application = FastAPI()
    application.add_middleware(
        APIRateLimitMiddleware,
        window_seconds=60,
        default_limit=3,
        auth_limit=2,
        ingestion_limit=2,
        ingestion_ip_limit=5,
    )

    @application.get("/api/v1/auth/me")
    def auth_me():
        return {"ok": True}

    @application.post("/api/v1/events")
    def ingest():
        return {"accepted": True}

    @application.get("/api/v1/alerts")
    def alerts():
        return {"alerts": []}

    @application.get("/api/v1/health")
    def health():
        return {"status": "healthy"}

    with TestClient(application) as client:
        yield client


def test_authentication_endpoint_is_limited_by_client_ip(limited_client):
    first = limited_client.get("/api/v1/auth/me")
    second = limited_client.get("/api/v1/auth/me")
    third = limited_client.get("/api/v1/auth/me")

    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 429
    assert third.json()["category"] == "auth"
    assert third.headers["retry-after"].isdigit()
    assert third.headers["ratelimit-limit"] == "2"
    assert third.headers["ratelimit-remaining"] == "0"


def test_event_ingestion_uses_token_fingerprint_buckets(limited_client):
    token_a = {"Authorization": "Bearer " + ("a" * 48)}
    token_b = {"Authorization": "Bearer " + ("b" * 48)}

    assert limited_client.post("/api/v1/events", headers=token_a).status_code == 200
    assert limited_client.post("/api/v1/events", headers=token_a).status_code == 200
    blocked = limited_client.post("/api/v1/events", headers=token_a)
    independent = limited_client.post("/api/v1/events", headers=token_b)

    assert blocked.status_code == 429
    assert blocked.json()["category"] == "event-ingestion"
    assert independent.status_code == 200


def test_forwarded_ip_header_cannot_bypass_client_ip_limit(limited_client):
    assert limited_client.get("/api/v1/auth/me").status_code == 200
    assert limited_client.get(
        "/api/v1/auth/me",
        headers={"X-Forwarded-For": "203.0.113.10"},
    ).status_code == 200
    blocked = limited_client.get(
        "/api/v1/auth/me",
        headers={"X-Forwarded-For": "198.51.100.20"},
    )

    assert blocked.status_code == 429


def test_general_api_traffic_has_a_separate_limit(limited_client):
    assert limited_client.get("/api/v1/alerts").status_code == 200
    assert limited_client.get("/api/v1/alerts").status_code == 200
    assert limited_client.get("/api/v1/alerts").status_code == 200
    blocked = limited_client.get("/api/v1/alerts")

    assert blocked.status_code == 429
    assert blocked.json()["category"] == "api"


def test_public_health_endpoint_is_not_rate_limited(limited_client):
    for _ in range(5):
        response = limited_client.get("/api/v1/health")
        assert response.status_code == 200
        assert "ratelimit-limit" not in response.headers


def test_rate_limit_configuration_rejects_invalid_values():
    application = FastAPI()

    with pytest.raises(ValueError):
        APIRateLimitMiddleware(application, window_seconds=0)

    with pytest.raises(ValueError):
        APIRateLimitMiddleware(application, default_limit=-1)

    with pytest.raises(TypeError):
        APIRateLimitMiddleware(application, auth_limit=True)

def test_event_ingestion_ip_limit_cannot_be_bypassed_by_rotating_tokens(limited_client):
    for index in range(5):
        token = {"Authorization": "Bearer " + str(index).zfill(48)}
        response = limited_client.post("/api/v1/events", headers=token)
        assert response.status_code == 200

    rotated_token = {"Authorization": "Bearer " + ("z" * 48)}
    blocked = limited_client.post("/api/v1/events", headers=rotated_token)

    assert blocked.status_code == 429
    assert blocked.json()["category"] == "event-ingestion"
