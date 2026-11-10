"""Security-focused API regression tests.

These tests exercise authentication, role separation, and strict request
validation through the public HTTP interface.
"""

from conftest import ANALYST_TEST_TOKEN, APPROVER_TEST_TOKEN


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_protected_events_endpoint_rejects_missing_credentials(client):
    response = client.get(
        "/api/v1/events",
        headers={"Authorization": ""},
    )

    assert response.status_code == 401
    assert response.headers.get("www-authenticate") == "Bearer"


def test_protected_events_endpoint_rejects_invalid_token(client):
    response = client.get(
        "/api/v1/events",
        headers=bearer("invalid-token"),
    )

    assert response.status_code == 401
    assert response.headers.get("www-authenticate") == "Bearer"


def test_analyst_cannot_approve_response(client):
    response = client.post(
        "/api/v1/response/1/approve",
        json={"reason": "Security regression test"},
        headers=bearer(ANALYST_TEST_TOKEN),
    )

    assert response.status_code == 403
    assert "Approver" in response.json()["detail"]


def test_analyst_cannot_inspect_approver_only_audit_integrity(client):
    response = client.get(
        "/api/v1/response/1/audit-integrity",
        headers=bearer(ANALYST_TEST_TOKEN),
    )

    assert response.status_code == 403


def test_approver_cannot_create_analyst_investigation_note(
    client,
    seeded_alert,
):
    response = client.post(
        f"/api/v1/alerts/{seeded_alert}/notes",
        json={"content": "This action must be analyst-only."},
        headers=bearer(APPROVER_TEST_TOKEN),
    )

    assert response.status_code == 403


def test_event_ingestion_rejects_invalid_ip_address(client):
    response = client.post(
        "/api/v1/events",
        json={
            "event_type": "authentication_failed",
            "source_ip": "not-an-ip-address",
        },
        headers=bearer(ANALYST_TEST_TOKEN),
    )

    assert response.status_code == 422


def test_event_ingestion_rejects_unexpected_request_fields(client):
    response = client.post(
        "/api/v1/events",
        json={
            "event_type": "authentication_failed",
            "unexpected_admin": True,
        },
        headers=bearer(ANALYST_TEST_TOKEN),
    )

    assert response.status_code == 422


def test_event_listing_rejects_excessive_limit(client):
    response = client.get(
        "/api/v1/events?limit=1001",
        headers=bearer(ANALYST_TEST_TOKEN),
    )

    assert response.status_code == 400


def test_authentication_fails_closed_when_credentials_are_not_configured(
    client,
    monkeypatch,
):
    monkeypatch.delenv("AEGIS_ANALYST_TOKEN")
    monkeypatch.delenv("AEGIS_APPROVER_TOKEN")

    response = client.get(
        "/api/v1/auth/me",
        headers=bearer(ANALYST_TEST_TOKEN),
    )

    assert response.status_code == 503
    assert "not configured" in response.json()["detail"].lower()


def test_authentication_fails_closed_when_roles_share_a_token(
    client,
    monkeypatch,
):
    shared_token = "shared-test-token-" + ("z" * 40)
    monkeypatch.setenv("AEGIS_ANALYST_TOKEN", shared_token)
    monkeypatch.setenv("AEGIS_APPROVER_TOKEN", shared_token)

    response = client.get(
        "/api/v1/auth/me",
        headers=bearer(shared_token),
    )

    assert response.status_code == 503
    assert "different" in response.json()["detail"].lower()



def assert_security_headers(response):
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("cross-origin-resource-policy") == "same-origin"


def test_security_headers_are_present_on_api_responses(client):
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert_security_headers(response)


def test_security_headers_are_present_on_not_found_responses(client):
    response = client.get("/api/v1/route-that-does-not-exist")

    assert response.status_code == 404
    assert_security_headers(response)


def test_security_headers_are_present_on_request_limit_errors(client):
    response = client.post(
        "/api/v1/events",
        content=b"x" * 1_048_577,
    )

    assert response.status_code == 413
    assert_security_headers(response)
