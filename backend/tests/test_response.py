import pytest

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
