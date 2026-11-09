import pytest
from fastapi.testclient import TestClient

from app.main import app
from app import database


ANALYST_TOKEN = "a" * 48
APPROVER_TOKEN = "b" * 48


@pytest.mark.parametrize(
    "method,path,payload",
    [
        ("GET", "/api/v1/events", None),
        ("GET", "/api/v1/alerts", None),
        ("GET", "/api/v1/detection/rules", None),
        ("GET", "/api/v1/correlations", None),
        ("GET", "/api/v1/mitre/techniques", None),
        ("GET", "/api/v1/intelligence/ip/8.8.8.8", None),
        ("GET", "/api/v1/response/history", None),
        (
            "POST",
            "/api/v1/events",
            {"event_type": "authentication_failed"},
        ),
    ],
)
def test_operational_api_requires_bearer_authentication(
    isolated_database,
    method,
    path,
    payload,
):
    with TestClient(app) as unauthenticated_client:
        response = unauthenticated_client.request(
            method,
            path,
            json=payload,
        )

    assert response.status_code == 401
    assert "Bearer" in response.headers.get("www-authenticate", "")


def test_invalid_bearer_token_is_rejected(isolated_database):
    with TestClient(
        app,
        headers={"Authorization": "Bearer invalid-token"},
    ) as test_client:
        response = test_client.get("/api/v1/alerts")

    assert response.status_code == 401


def test_health_endpoint_remains_public(isolated_database):
    with TestClient(app) as test_client:
        response = test_client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_authenticated_session_returns_server_derived_identity(
    client,
):
    response = client.get("/api/v1/auth/me")

    assert response.status_code == 200
    assert response.json() == {
        "actor_id": "analyst-alpha",
        "role": "analyst",
    }


def test_approver_can_read_but_cannot_perform_analyst_operations(
    isolated_database,
    seeded_alert,
):
    with TestClient(
        app,
        headers={
            "Authorization": f"Bearer {APPROVER_TOKEN}",
        },
    ) as approver_client:
        read_response = approver_client.get(
            f"/api/v1/alerts/{seeded_alert}"
        )
        write_response = approver_client.post(
            f"/api/v1/alerts/{seeded_alert}/notes",
            json={"content": "Attempted analyst-only note."},
        )

    assert read_response.status_code == 200
    assert write_response.status_code == 403


def test_analyst_cannot_inspect_approver_only_response_audit(
    client,
):
    response = client.get(
        "/api/v1/response/1/audit-integrity"
    )

    assert response.status_code == 403


def test_correlation_status_rejects_caller_supplied_actor(
    client,
    seeded_correlation,
):
    response = client.patch(
        f"/api/v1/correlations/{seeded_correlation}/status",
        json={
            "status": "investigating",
            "actor": "administrator",
        },
    )

    assert response.status_code == 422
    assert "actor" in response.text


def test_correlation_note_rejects_caller_supplied_author(
    client,
    seeded_correlation,
):
    response = client.post(
        f"/api/v1/correlations/{seeded_correlation}/notes",
        json={
            "author": "administrator",
            "content": "Attempted identity spoof.",
        },
    )

    assert response.status_code == 422
    assert "author" in response.text


def test_correlation_audit_identity_comes_from_authenticated_actor(
    client,
    seeded_correlation,
):
    update = client.patch(
        f"/api/v1/correlations/{seeded_correlation}/status",
        json={"status": "investigating"},
    )
    assert update.status_code == 200

    with database.get_connection() as connection:
        audit = connection.execute(
            """
            SELECT actor
            FROM correlation_audit_log
            WHERE correlation_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (seeded_correlation,),
        ).fetchone()

    assert audit["actor"] == "analyst-alpha"


def test_alert_audit_identity_comes_from_authenticated_actor(
    client,
    seeded_alert,
):
    response = client.post(
        f"/api/v1/alerts/{seeded_alert}/notes",
        json={"content": "Authenticated analyst investigation note."},
    )

    assert response.status_code == 201
    assert response.json()["note"]["author"] == "analyst-alpha"

    with database.get_connection() as connection:
        timeline = connection.execute(
            """
            SELECT actor
            FROM incident_timeline
            WHERE alert_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (seeded_alert,),
        ).fetchone()
        audit = connection.execute(
            """
            SELECT actor
            FROM alert_audit_log
            WHERE alert_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (seeded_alert,),
        ).fetchone()

    assert timeline["actor"] == "analyst-alpha"
    assert audit["actor"] == "analyst-alpha"



def test_approver_cannot_trigger_threat_intelligence_enrichment(
    isolated_database,
):
    with TestClient(
        app,
        headers={"Authorization": f"Bearer {APPROVER_TOKEN}"},
    ) as approver_client:
        response = approver_client.post(
            "/api/v1/intelligence/ip",
            json={"ip_address": "8.8.8.8"},
        )

    assert response.status_code == 403
    assert response.json()["detail"] == "Analyst permissions are required."
