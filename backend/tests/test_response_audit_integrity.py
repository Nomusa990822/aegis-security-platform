
import copy

import pytest

from app import database
from app.response.audit import validate_response_audit
from app.response.engine import ResponseEngine
from app.response.models import (
    ExecutionMode,
    ResponseAction,
    ResponseRequest,
)
from app.response.repository import (
    decide_response,
    get_response_record,
    save_response,
    simulate_response,
)


def create_response():
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
                "Audit Integrity Test",
                "high",
                "Testing response audit consistency",
                "8.8.8.8",
                "AEGIS-AUTH-001",
                "2026-11-06T10:00:00+00:00",
                "open",
            ),
        )

        alert_id = cursor.lastrowid
        connection.commit()

        request = ResponseRequest(
            alert_id=alert_id,
            action=ResponseAction.BLOCK_IP,
            target="8.8.8.8",
            mode=ExecutionMode.DRY_RUN,
            requested_by="analyst-alpha",
        )

        result = ResponseEngine().request_approval(request)

        return save_response(connection, request, result)


def get_record(response_id):
    with database.get_connection() as connection:
        return get_response_record(connection, response_id)


def approve_response(response_id):
    with database.get_connection() as connection:
        return decide_response(
            connection=connection,
            response_id=response_id,
            actor_id="approver-beta",
            decision="approved",
            reason="Approved for testing.",
        )


def reject_response(response_id):
    with database.get_connection() as connection:
        return decide_response(
            connection=connection,
            response_id=response_id,
            actor_id="approver-beta",
            decision="rejected",
            reason="Rejected for testing.",
        )


def simulate_approved_response(response_id):
    with database.get_connection() as connection:
        return simulate_response(
            connection=connection,
            response_id=response_id,
            actor_id="analyst-alpha",
        )


def test_pending_response_has_valid_audit(isolated_database):
    response_id = create_response()

    result = validate_response_audit(get_record(response_id))

    assert result["valid"] is True
    assert result["errors"] == []


@pytest.mark.parametrize(
    "decision",
    [
        approve_response,
        reject_response,
    ],
)
def test_decided_response_has_valid_audit(
    isolated_database,
    decision,
):
    response_id = create_response()

    assert decision(response_id) == "updated"

    result = validate_response_audit(get_record(response_id))

    assert result["valid"] is True
    assert result["errors"] == []


def test_simulated_response_has_valid_audit(isolated_database):
    response_id = create_response()

    assert approve_response(response_id) == "updated"
    assert simulate_approved_response(response_id) == "simulated"

    result = validate_response_audit(get_record(response_id))

    assert result["valid"] is True
    assert result["errors"] == []


def test_validator_detects_missing_approval_event(isolated_database):
    response_id = create_response()
    assert approve_response(response_id) == "updated"

    record = get_record(response_id)
    record["audit_log"] = [
        record["audit_log"][0],
    ]

    result = validate_response_audit(record)

    assert result["valid"] is False
    assert any(
        "sequence" in error.lower()
        for error in result["errors"]
    )


def test_validator_detects_modified_audit_actor(isolated_database):
    response_id = create_response()
    assert approve_response(response_id) == "updated"

    record = get_record(response_id)
    record["audit_log"][1]["actor"] = "unauthorised-user"

    result = validate_response_audit(record)

    assert result["valid"] is False
    assert any(
        "actor" in error.lower()
        for error in result["errors"]
    )


def test_validator_detects_wrong_alert_reference(isolated_database):
    response_id = create_response()

    record = get_record(response_id)
    record["audit_log"][0]["alert_id"] = 999999

    result = validate_response_audit(record)

    assert result["valid"] is False
    assert any(
        "wrong alert" in error.lower()
        for error in result["errors"]
    )


def test_validator_detects_simulation_claiming_execution(
    isolated_database,
):
    response_id = create_response()

    assert approve_response(response_id) == "updated"
    assert simulate_approved_response(response_id) == "simulated"

    record = get_record(response_id)

    record["audit_log"][2]["details"]["firewall_modified"] = True

    result = validate_response_audit(record)

    assert result["valid"] is False
    assert any(
        "firewall_modified" in error
        for error in result["errors"]
    )


def test_validator_does_not_modify_original_record(isolated_database):
    response_id = create_response()
    record = get_record(response_id)

    original = copy.deepcopy(record)

    validate_response_audit(record)

    assert record == original


def test_validator_rejects_missing_audit_log():
    result = validate_response_audit({
        "id": 1,
        "alert_id": 1,
        "status": "pending_approval",
        "audit_log": None,
    })

    assert result["valid"] is False
    assert result["errors"]
