import copy

import pytest

from app.response.audit import validate_response_audit


CREATED = "2026-11-06T10:00:00+00:00"
DECIDED = "2026-11-06T10:01:00+00:00"
SIMULATED = "2026-11-06T10:03:00+00:00"


def make_record(status="pending_approval"):
    policy_allowed = status != "policy_rejected"

    initial_status = (
        "rejected" if status == "policy_rejected"
        else "pending_approval"
    )

    final_status = (
        "rejected" if status == "policy_rejected"
        else status
    )

    record = {
        "id": 10,
        "alert_id": 20,
        "action": "block_ip",
        "target": "8.8.8.8",
        "mode": "dry_run",
        "requested_by": "analyst alpha",
        "status": final_status,
        "policy_allowed": policy_allowed,
        "approval_required": True,
        "executed": False,
        "simulated": status == "simulated",
        "created_at": CREATED,
        "decided_by": None,
        "decision_at": None,
        "decision_reason": None,
    }

    creation = {
        "id": 100,
        "response_id": 10,
        "alert_id": 20,
        "event": "response_request_created",
        "actor": "analyst alpha",
        "created_at": CREATED,
        "details": {
            "status": initial_status,
            "action": "block_ip",
            "target": "8.8.8.8",
            "policy_allowed": policy_allowed,
            "approval_required": True,
            "executed": False,
            "simulated": False,
        },
    }

    record["audit_log"] = [creation]

    if status in ("approved", "rejected", "simulated"):
        decision_status = (
            "approved" if status == "simulated" else status
        )

        record["decided_by"] = "approver beta"
        record["decision_at"] = DECIDED
        record["decision_reason"] = "Approved for testing."

        record["audit_log"].append({
            "id": 101,
            "response_id": 10,
            "alert_id": 20,
            "event": (
                "response_approved"
                if status in ("approved", "simulated")
                else "response_rejected"
            ),
            "actor": "approver beta",
            "created_at": DECIDED,
            "details": {
                "previous_status": "pending_approval",
                "new_status": decision_status,
                "decided_by": "approver beta",
                "decision_reason": "Approved for testing.",
                "executed": False,
                "simulated": False,
            },
        })

    if status == "simulated":
        record["audit_log"].append({
            "id": 102,
            "response_id": 10,
            "alert_id": 20,
            "event": "response_simulated",
            "actor": "analyst alpha",
            "created_at": SIMULATED,
            "details": {
                "simulation_mode": "dry_run",
                "action": "block_ip",
                "target": "8.8.8.8",
                "outcome": "would_block",
                "firewall_modified": False,
                "network_modified": False,
                "operating_system_command_executed": False,
                "executed": False,
                "simulated": True,
            },
        })

    return record


@pytest.mark.parametrize(
    "status",
    [
        "pending_approval",
        "approved",
        "rejected",
        "simulated",
        "policy_rejected",
    ],
)
def test_valid_lifecycle_records_pass(status):
    record = make_record(status)

    result = validate_response_audit(record)

    assert result["valid"] is True
    assert result["errors"] == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("policy_allowed", False),
        ("approval_required", False),
        ("executed", True),
        ("simulated", True),
    ],
)
def test_creation_record_mismatches_are_detected(field, value):
    record = make_record()
    record[field] = value

    result = validate_response_audit(record)

    assert result["valid"] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("policy_allowed", False),
        ("approval_required", False),
        ("executed", True),
        ("simulated", True),
    ],
)
def test_creation_event_mismatches_are_detected(field, value):
    record = make_record()
    record["audit_log"][0]["details"][field] = value

    result = validate_response_audit(record)

    assert result["valid"] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("previous_status", "approved"),
        ("new_status", "rejected"),
        ("decided_by", "unauthorised-user"),
        ("decision_reason", "Tampered reason"),
        ("executed", True),
        ("simulated", True),
    ],
)
def test_decision_event_tampering_is_detected(field, value):
    record = make_record("approved")
    record["audit_log"][1]["details"][field] = value

    result = validate_response_audit(record)

    assert result["valid"] is False


def test_response_decision_reason_tampering_is_detected():
    record = make_record("approved")
    record["decision_reason"] = "Different reason"

    result = validate_response_audit(record)

    assert result["valid"] is False


def test_simulation_target_tampering_is_detected():
    record = make_record("simulated")
    record["audit_log"][2]["details"]["target"] = "1.1.1.1"

    result = validate_response_audit(record)

    assert result["valid"] is False


def test_simulation_action_tampering_is_detected():
    record = make_record("simulated")
    record["audit_log"][2]["details"]["action"] = "other_action"

    result = validate_response_audit(record)

    assert result["valid"] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("firewall_modified", True),
        ("network_modified", True),
        ("operating_system_command_executed", True),
        ("executed", True),
        ("simulated", False),
        ("outcome", "blocked"),
        ("simulation_mode", "live"),
    ],
)
def test_simulation_safety_tampering_is_detected(field, value):
    record = make_record("simulated")
    record["audit_log"][2]["details"][field] = value

    result = validate_response_audit(record)

    assert result["valid"] is False


def test_non_chronological_timestamps_are_detected():
    record = make_record("simulated")
    record["audit_log"][2]["created_at"] = CREATED

    result = validate_response_audit(record)

    assert result["valid"] is False


def test_creation_timestamp_mismatch_is_detected():
    record = make_record()
    record["created_at"] = DECIDED

    result = validate_response_audit(record)

    assert result["valid"] is False


def test_wrong_simulation_actor_is_detected():
    record = make_record("simulated")
    record["audit_log"][2]["actor"] = "different-analyst"

    result = validate_response_audit(record)

    assert result["valid"] is False


def test_approver_rejection_must_follow_pending_request():
    record = make_record("rejected")
    record["audit_log"][0]["details"]["status"] = "rejected"

    result = validate_response_audit(record)

    assert result["valid"] is False


def test_validator_does_not_modify_record():
    record = make_record("simulated")
    original = copy.deepcopy(record)

    validate_response_audit(record)

    assert record == original