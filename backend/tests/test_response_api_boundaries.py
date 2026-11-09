
import pytest

from app import database


ANALYST_TOKEN = "a" * 48
APPROVER_TOKEN = "b" * 48


def analyst_headers():
    return {
        "Authorization": f"Bearer {ANALYST_TOKEN}",
    }


def approver_headers():
    return {
        "Authorization": f"Bearer {APPROVER_TOKEN}",
    }


def create_alert(source_ip="8.8.8.8"):
    with database.get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO security_alerts (
                title,
                severity,
                description,
                source_ip,
                detection_rule,
                created_at,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "API Boundary Test Alert",
                "high",
                "Testing response API boundary validation",
                source_ip,
                "AEGIS-AUTH-001",
                "2026-11-06T10:00:00+00:00",
                "open",
            ),
        )

        connection.commit()
        return cursor.lastrowid


def create_pending_response(client):
    alert_id = create_alert()

    response = client.post(
        "/api/v1/response/preview",
        json={
            "alert_id": alert_id,
            "action": "block_ip",
            "target": "8.8.8.8",
        },
    )

    assert response.status_code == 201
    assert response.json()["result"]["status"] == "pending_approval"

    return response.json()["response_id"]


def get_response(response_id):
    with database.get_connection() as connection:
        return connection.execute(
            """
            SELECT *
            FROM response_records
            WHERE id = ?
            """,
            (response_id,),
        ).fetchone()


# --------------------------------------------------
# PREVIEW REQUEST VALIDATION
# --------------------------------------------------

def test_preview_rejects_missing_required_fields(client):
    response = client.post(
        "/api/v1/response/preview",
        json={},
    )

    assert response.status_code == 422


@pytest.mark.parametrize(
    "payload",
    [
        {
            "alert_id": 1,
            "action": "delete_firewall",
            "target": "8.8.8.8",
        },
        {
            "alert_id": 1,
            "action": "block_ip",
            "target": "",
        },
        {
            "alert_id": 1,
            "action": "block_ip",
            "target": " " * 10,
        },
    ],
)
def test_preview_rejects_invalid_payload_values(client, payload):
    response = client.post(
        "/api/v1/response/preview",
        json=payload,
    )

    assert response.status_code == 422


def test_preview_rejects_malformed_target_ip(client):
    alert_id = create_alert()

    response = client.post(
        "/api/v1/response/preview",
        json={
            "alert_id": alert_id,
            "action": "block_ip",
            "target": "not-an-ip",
        },
    )

    assert response.status_code == 422
    assert "valid IP address" in response.json()["detail"]


def test_preview_rejects_nonexistent_alert(client):
    response = client.post(
        "/api/v1/response/preview",
        json={
            "alert_id": 999999,
            "action": "block_ip",
            "target": "8.8.8.8",
        },
    )

    assert response.status_code == 404


@pytest.mark.parametrize(
    "source_ip",
    [
        None,
        "invalid-source-ip",
    ],
)
def test_preview_rejects_alert_without_valid_source_ip(
    client,
    source_ip,
):
    alert_id = create_alert(source_ip=source_ip)

    response = client.post(
        "/api/v1/response/preview",
        json={
            "alert_id": alert_id,
            "action": "block_ip",
            "target": "8.8.8.8",
        },
    )

    assert response.status_code == 422


def test_preview_does_not_accept_a_different_target(client):
    alert_id = create_alert(source_ip="8.8.8.8")

    response = client.post(
        "/api/v1/response/preview",
        json={
            "alert_id": alert_id,
            "action": "block_ip",
            "target": "1.1.1.1",
        },
    )

    assert response.status_code == 422
    assert "must match" in response.json()["detail"]


def test_preview_attributes_request_to_authenticated_actor(client):
    alert_id = create_alert()

    response = client.post(
        "/api/v1/response/preview",
        json={
            "alert_id": alert_id,
            "action": "block_ip",
            "target": "8.8.8.8",
        },
        headers=analyst_headers(),
    )

    assert response.status_code == 201

    response_id = response.json()["response_id"]
    record = get_response(response_id)

    assert record["requested_by"] == "analyst-alpha"


# --------------------------------------------------
# APPROVAL AND REJECTION VALIDATION
# --------------------------------------------------

def test_approval_rejects_reason_longer_than_limit(client):
    response_id = create_pending_response(client)

    response = client.post(
        f"/api/v1/response/{response_id}/approve",
        json={
            "reason": "A" * 501,
        },
        headers=approver_headers(),
    )

    assert response.status_code == 422

    detail = client.get(
        f"/api/v1/response/history/{response_id}",
    )

    assert detail.status_code == 200
    assert detail.json()["status"] == "pending_approval"
    assert len(detail.json()["audit_log"]) == 1


def test_rejection_rejects_reason_longer_than_limit(client):
    response_id = create_pending_response(client)

    response = client.post(
        f"/api/v1/response/{response_id}/reject",
        json={
            "reason": "R" * 501,
        },
        headers=approver_headers(),
    )

    assert response.status_code == 422

    detail = client.get(
        f"/api/v1/response/history/{response_id}",
    )

    assert detail.status_code == 200
    assert detail.json()["status"] == "pending_approval"
    assert len(detail.json()["audit_log"]) == 1


@pytest.mark.parametrize(
    "endpoint",
    [
        "approve",
        "reject",
    ],
)
def test_decision_endpoints_reject_non_positive_ids(
    client,
    endpoint,
):
    response = client.post(
        f"/api/v1/response/0/{endpoint}",
        json={},
        headers=approver_headers(),
    )

    assert response.status_code == 400


# --------------------------------------------------
# HISTORY API VALIDATION
# --------------------------------------------------

@pytest.mark.parametrize(
    "limit",
    [
        0,
        501,
    ],
)
def test_history_rejects_out_of_range_limits(client, limit):
    response = client.get(
        f"/api/v1/response/history?limit={limit}",
    )

    assert response.status_code == 422


def test_history_detail_rejects_non_positive_id(client):
    response = client.get(
        "/api/v1/response/history/0",
    )

    assert response.status_code == 400


def test_history_detail_returns_404_for_unknown_id(client):
    response = client.get(
        "/api/v1/response/history/999999",
    )

    assert response.status_code == 404
