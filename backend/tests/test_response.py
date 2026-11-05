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


# --------------------------------------------------
# RESPONSE ENGINE UNIT TESTS
# --------------------------------------------------

def test_valid_public_ip_is_simulated(engine):
    result = engine.execute(make_request())

    assert result.status == ResponseStatus.SIMULATED
    assert result.policy_allowed is True
    assert result.approval_required is True
    assert result.executed is False
    assert result.simulated is True


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
    result = engine.execute(make_request(target=target))

    assert result.status == ResponseStatus.REJECTED
    assert result.policy_allowed is False
    assert result.executed is False
    assert result.simulated is False


def test_invalid_ip_is_rejected(engine):
    result = engine.execute(
        make_request(target="not-an-ip")
    )

    assert result.status == ResponseStatus.REJECTED
    assert result.executed is False


def test_invalid_alert_id_is_rejected(engine):
    result = engine.execute(
        make_request(alert_id=0)
    )

    assert result.status == ResponseStatus.REJECTED
    assert result.policy_allowed is False


def test_blank_requester_is_rejected(engine):
    result = engine.execute(
        make_request(requested_by="   ")
    )

    assert result.status == ResponseStatus.REJECTED
    assert result.policy_allowed is False


def test_dry_run_never_executes_real_action(engine):
    result = engine.execute(make_request())

    assert result.mode == ExecutionMode.DRY_RUN.value
    assert result.executed is False
    assert result.simulated is True


def test_response_result_serializes_to_dictionary(engine):
    result = engine.execute(make_request())
    data = result.to_dict()

    assert data["status"] == "simulated"
    assert data["action"] == "block_ip"
    assert data["target"] == "8.8.8.8"
    assert data["mode"] == "dry_run"
    assert data["executed"] is False
    assert data["simulated"] is True
    assert isinstance(data["reasons"], list)


def test_policy_requires_approval():
    policy = ResponsePolicyEngine()
    decision = policy.evaluate(make_request())

    assert decision.allowed is True
    assert decision.approval_required is True


# --------------------------------------------------
# RESPONSE API INTEGRATION TESTS
# --------------------------------------------------

def test_preview_requires_target_to_match_alert(client):
    alert_id = create_alert(source_ip="8.8.8.8")

    response = client.post(
        "/api/v1/response/preview",
        json={
            "alert_id": alert_id,
            "action": "block_ip",
            "target": "1.1.1.1",
            "requested_by": "integration-test",
        },
    )

    assert response.status_code == 422
    assert "must match" in response.json()["detail"]


def test_valid_preview_is_persisted_with_audit_log(client):
    alert_id = create_alert(source_ip="8.8.8.8")

    response = client.post(
        "/api/v1/response/preview",
        json={
            "alert_id": alert_id,
            "action": "block_ip",
            "target": "8.8.8.8",
            "requested_by": "integration-test",
        },
    )

    assert response.status_code == 201

    payload = response.json()
    response_id = payload["response_id"]

    assert payload["result"]["status"] == "simulated"
    assert payload["result"]["executed"] is False
    assert payload["result"]["simulated"] is True

    history = client.get("/api/v1/response/history")

    assert history.status_code == 200
    assert history.json()["count"] == 1

    detail = client.get(
        f"/api/v1/response/history/{response_id}"
    )

    assert detail.status_code == 200

    record = detail.json()

    assert record["alert_id"] == alert_id
    assert record["requested_by"] == "integration-test"
    assert len(record["audit_log"]) == 1
    assert record["audit_log"][0]["event"] == (
        "response_preview_created"
    )
    assert record["executed"] is False


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
