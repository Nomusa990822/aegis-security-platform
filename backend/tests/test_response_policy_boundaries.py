
import pytest

from app.response.engine import ResponseEngine
from app.response.models import (
    ExecutionMode,
    ResponseAction,
    ResponseRequest,
    ResponseStatus,
)
from app.response.policy import ResponsePolicyEngine


def make_request(target):
    return ResponseRequest(
        alert_id=1,
        action=ResponseAction.BLOCK_IP,
        target=target,
        mode=ExecutionMode.DRY_RUN,
        requested_by="security-analyst",
    )


@pytest.mark.parametrize(
    "target",
    [
        "8.8.8.8",
        "1.1.1.1",
        "9.9.9.9",
        "2001:4860:4860::8888",
        "2606:4700:4700::1111",
    ],
)
def test_globally_routable_addresses_pass_policy(target):
    decision = ResponsePolicyEngine().evaluate(
        make_request(target)
    )

    assert decision.allowed is True
    assert decision.approval_required is True


@pytest.mark.parametrize(
    "target",
    [
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.1.1",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "::",
        "::1",
        "fe80::1",
        "ff02::1",
        "2001:db8::1",
    ],
)
def test_non_global_addresses_are_rejected(target):
    decision = ResponsePolicyEngine().evaluate(
        make_request(target)
    )

    assert decision.allowed is False
    assert decision.approval_required is True
    assert any(
        "globally routable" in reason
        for reason in decision.reasons
    )


def test_approved_policy_still_never_executes_real_action():
    result = ResponseEngine().execute(
        make_request("8.8.8.8")
    )

    assert result.status == ResponseStatus.SIMULATED
    assert result.policy_allowed is True
    assert result.approval_required is True
    assert result.executed is False
    assert result.simulated is True
    assert result.mode == ExecutionMode.DRY_RUN.value


def test_rejected_address_never_executes_or_simulates():
    result = ResponseEngine().execute(
        make_request("192.168.1.10")
    )

    assert result.status == ResponseStatus.REJECTED
    assert result.policy_allowed is False
    assert result.executed is False
    assert result.simulated is False
