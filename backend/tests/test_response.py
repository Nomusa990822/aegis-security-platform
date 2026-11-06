
import pytest

from app import database
from app.response.engine import ResponseEngine
from app.response.models import (
    ExecutionMode,
    ResponseAction,
    ResponseRequest,
    ResponseStatus,
)
from app.response.policy import ResponsePolicyEngine


ANALYST_TOKEN = "a" * 48
APPROVER_TOKEN = "b" * 48


@pytest.fixture
def engine():
    return ResponseEngine()


def make_request(
    target="8.8.8.8",
    alert_id=1,
    requested_by="analyst",
):
    return ResponseRequest(
        alert_id=alert_id,
        action=ResponseAction.BLOCK_IP,
        target=target,
        mode=ExecutionMode.DRY_RUN,
        requested_by=requested_by,
    )


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
                "Response API Test Alert",
                "high",
                "Testing controlled response validation",
                source_ip,
                "AEGIS-AUTH-001",
                "2026-11-06T10:00:00+00:00",
                "open",
            ),
        )
        connection.commit()
        return cursor.lastrowid


def analyst_headers():
    return {
        "Authorization": f"Bearer {ANALYST_TOKEN}",
    }


def approver_headers():
    return {
        "Authorization": f"Bearer {APPROVER_TOKEN}",
    }


# --------------------------------------------------
# RESPONSE ENGINE UNIT TESTS
# --------------------------------------------------

def test_valid_public_ip_enters_pending_approval(engine):
    result = engine.request_approval(make_request())

    assert result.status == ResponseStatus.PENDING_APPROVAL
    assert result.policy_allowed is True
    assert result.approval_required is True
    assert result.executed is False
    assert result.simulated is False


@pytest.mark.parametrize(
    "target",
    [
        "192.168.1.10",
        "127.0.0.1",
        "10.0.0.5",
        "172.16.0.1",
    ],
)
def test_non_global_ip_is_rejected(engine, target):
    result = engine.request_approval(
        make_request(target=target)
    )

    assert result.status == ResponseStatus.REJECTED
    assert result.policy_allowed is False
    assert result.executed is False
    assert result.simulated is False


def test_invalid_ip_is_rejected(engine):
    result = engine.request_approval(
        make_request(target="not-an-ip")
    )

    assert result.status == ResponseStatus.REJECTED
    assert result.executed is False
    assert result.simulated is False


def test_invalid_alert_id_is_rejected(engine):
    result = engine.request_approval(
        make_request(alert_id=0)
    )

    assert result.status == ResponseStatus.REJECTED
    assert result.policy_allowed is False


def test_blank_requester_is_rejected(engine):
    result = engine.request_approval(
        make_request(requested_by="   ")
    )

    assert result.status == ResponseStatus.REJECTED
    assert result.policy_allowed is False


def test_request_approval_never_simulates_or_executes(engine):
    result = engine.request_approval(make_request())

    assert result.mode == ExecutionMode.DRY_RUN.value
    assert result.executed is False
    assert result.simulated is False
    assert result.status == ResponseStatus.PENDING_APPROVAL


def test_response_result_serializes_to_dictionary(engine):
    result = engine.request_approval(make_request())
    data = result.to_dict()

    assert data["status"] == "pending_approval"
    assert data["action"] == "block_ip"
    assert data["target"] == "8.8.8.8"
    assert data["mode"] == "dry_run"
    assert data["executed"] is False
    assert data["simulated"] is False
    assert isinstance(data["reasons"], list)


def test_policy_requires_approval():
    policy = ResponsePolicyEngine()
    decision = policy.evaluate(make_request())

    assert decision.allowed is True
    assert decision.approval_required is True


# --------------------------------------------------
# RESPONSE API AUTHENTICATION TESTS
# --------------------------------------------------

def test_response_request_requires_authentication(
    client,
    seeded_alert,
):
    client.headers.pop("Authorization", None)
    response = client.post(
        "/api/v1/response/preview",
        json={
            "alert_id": seeded_alert,
            "action": "block_ip",
            "target": "198.51.100.250",
        },
        headers={},
    )

    assert response.status_code == 401


def test_approver_cannot_submit_analyst_request(
    client,
    seeded_alert,
):
    response = client.post(
        "/api/v1/response/preview",
        json={
            "alert_id": seeded_alert,
            "action": "block_ip",
            "target": "198.51.100.250",
        },
        headers=approver_headers(),
    )

    assert response.status_code == 403


def test_history_requires_authentication(client):
    client.headers.pop("Authorization", None)
    response = client.get(
        "/api/v1/response/history",
        headers={},
    )

    assert response.status_code == 401


def test_approver_can_inspect_response_history(
    client,
    seeded_alert,
):
    created = client.post(
        "/api/v1/response/preview",
        json={
            "alert_id": seeded_alert,
            "action": "block_ip",
            "target": "198.51.100.250",
        },
    )

    assert created.status_code == 201

    history = client.get(
        "/api/v1/response/history",
        headers=approver_headers(),
    )

    assert history.status_code == 200
    assert history.json()["count"] == 1


# --------------------------------------------------
# RESPONSE API INTEGRATION TESTS
# --------------------------------------------------

def test_preview_requires_target_to_match_alert(
    client,
    seeded_alert,
):
    response = client.post(
        "/api/v1/response/preview",
        json={
            "alert_id": seeded_alert,
            "action": "block_ip",
            "target": "1.1.1.1",
        },
    )

    assert response.status_code == 422
    assert "must match" in response.json()["detail"]


def test_valid_request_is_persisted_pending_approval(client):
    alert_id = create_alert(source_ip="8.8.8.8")

    response = client.post(
        "/api/v1/response/preview",
        json={
            "alert_id": alert_id,
            "action": "block_ip",
            "target": "8.8.8.8",
        },
    )

    assert response.status_code == 201

    payload = response.json()
    response_id = payload["response_id"]

    assert payload["result"]["status"] == "pending_approval"
    assert payload["result"]["policy_allowed"] is True
    assert payload["result"]["approval_required"] is True
    assert payload["result"]["executed"] is False
    assert payload["result"]["simulated"] is False

    history = client.get("/api/v1/response/history")

    assert history.status_code == 200
    assert history.json()["count"] == 1

    detail = client.get(
        f"/api/v1/response/history/{response_id}"
    )

    assert detail.status_code == 200

    record = detail.json()

    assert record["alert_id"] == alert_id
    assert record["requested_by"] == "analyst-alpha"
    assert record["status"] == "pending_approval"
    assert record["executed"] is False
    assert record["simulated"] is False
    assert len(record["audit_log"]) == 1
    assert record["audit_log"][0]["event"] == (
        "response_request_created"
    )
    assert record["audit_log"][0]["actor"] == "analyst-alpha"

def test_client_cannot_spoof_requester_identity(
    client,
    seeded_alert,
):
    response = client.post(
        "/api/v1/response/preview",
        json={
            "alert_id": seeded_alert,
            "action": "block_ip",
            "target": "198.51.100.250",
            "requested_by": "approver-beta",
        },
    )

    assert response.status_code == 201

    response_id = response.json()["response_id"]

    detail = client.get(
        f"/api/v1/response/history/{response_id}"
    )

    assert detail.status_code == 200
    assert detail.json()["requested_by"] == "analyst-alpha"


@pytest.mark.parametrize(
    "source_ip",
    [
        None,
        "not-an-ip",
    ],
)
def test_alert_without_valid_source_ip_is_rejected(
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


def test_nonexistent_alert_is_rejected(client):
    response = client.post(
        "/api/v1/response/preview",
        json={
            "alert_id": 999999,
            "action": "block_ip",
            "target": "8.8.8.8",
        },
    )

    assert response.status_code == 404


def test_matching_private_ip_is_still_rejected_by_policy(client):
    alert_id = create_alert(source_ip="192.168.1.10")

    response = client.post(
        "/api/v1/response/preview",
        json={
            "alert_id": alert_id,
            "action": "block_ip",
            "target": "192.168.1.10",
        },
    )

    assert response.status_code == 201

    result = response.json()["result"]

    assert result["status"] == "rejected"
    assert result["policy_allowed"] is False
    assert result["executed"] is False
    assert result["simulated"] is False
