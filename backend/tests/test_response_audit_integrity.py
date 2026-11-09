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
    get_response_history,
    get_response_record,
    save_response,
    simulate_response,
)


def create_response(target="8.8.8.8"):
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
            target=target,
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


def test_policy_rejected_response_has_valid_audit(isolated_database):
    response_id = create_response(target="10.0.0.5")
    record = get_record(response_id)

    assert record["status"] == "rejected"
    assert record["decided_by"] is None
    assert record["decision_at"] is None
    assert len(record["audit_log"]) == 1
    assert record["audit_log"][0]["details"]["status"] == "rejected"

    result = validate_response_audit(record)

    assert result["valid"] is True
    assert result["errors"] == []


def test_policy_rejected_response_cannot_claim_approver(
    isolated_database,
):
    response_id = create_response(target="10.0.0.5")
    record = get_record(response_id)

    record["decided_by"] = "approver-beta"

    result = validate_response_audit(record)

    assert result["valid"] is False
    assert any(
        "approver" in error.lower()
        for error in result["errors"]
    )


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


def test_decision_rolls_back_when_audit_event_append_fails(
    isolated_database,
    monkeypatch,
):
    from app.response import repository

    response_id = create_response()
    before = get_record(response_id)

    def fail_audit_append(**kwargs):
        raise OSError("Simulated audit-event storage failure.")

    monkeypatch.setattr(
        repository,
        "append_audit_event",
        fail_audit_append,
    )

    with pytest.raises(OSError, match="Simulated audit-event storage failure"):
        with database.get_connection() as connection:
            decide_response(
                connection=connection,
                response_id=response_id,
                actor_id="approver-beta",
                decision="approved",
                reason="Must roll back if audit append fails.",
            )

    after = get_record(response_id)

    assert after["status"] == "pending_approval"
    assert after["decided_by"] is None
    assert after["decision_at"] is None
    assert after["decision_reason"] is None
    assert after["audit_log"] == before["audit_log"]

    with database.get_connection() as connection:
        head = connection.execute(
            """
            SELECT event_count, final_hash
            FROM response_audit_chain_heads
            WHERE response_id = ?
            """,
            (response_id,),
        ).fetchone()

    assert head["event_count"] == 1
    assert head["final_hash"] == before["audit_log"][-1]["event_hash"]


def test_simulation_rolls_back_when_audit_event_append_fails(
    isolated_database,
    monkeypatch,
):
    from app.response import repository

    response_id = create_response()
    assert approve_response(response_id) == "updated"
    before = get_record(response_id)

    def fail_audit_append(**kwargs):
        raise OSError("Simulated audit-event storage failure.")

    monkeypatch.setattr(
        repository,
        "append_audit_event",
        fail_audit_append,
    )

    with pytest.raises(OSError, match="Simulated audit-event storage failure"):
        with database.get_connection() as connection:
            simulate_response(
                connection=connection,
                response_id=response_id,
                actor_id="analyst-alpha",
            )

    after = get_record(response_id)

    assert after["status"] == "approved"
    assert after["simulated"] is False
    assert after["executed"] is False
    assert after["audit_log"] == before["audit_log"]

    with database.get_connection() as connection:
        head = connection.execute(
            """
            SELECT event_count, final_hash
            FROM response_audit_chain_heads
            WHERE response_id = ?
            """,
            (response_id,),
        ).fetchone()

    assert head["event_count"] == 2
    assert head["final_hash"] == before["audit_log"][-1]["event_hash"]


def test_decision_rolls_back_when_checkpoint_intent_preparation_fails(
    isolated_database,
    monkeypatch,
):
    from app.response import repository

    response_id = create_response()
    before = get_record(response_id)

    def fail_intent_preparation(connection, response_id):
        raise OSError("Simulated checkpoint-intent preparation failure.")

    monkeypatch.setattr(
        repository,
        "_prepare_audit_checkpoint_intent",
        fail_intent_preparation,
    )

    with pytest.raises(
        OSError,
        match="Simulated checkpoint-intent preparation failure",
    ):
        with database.get_connection() as connection:
            decide_response(
                connection=connection,
                response_id=response_id,
                actor_id="approver-beta",
                decision="approved",
                reason="Must roll back if checkpoint intent preparation fails.",
            )

    after = get_record(response_id)

    assert after["status"] == "pending_approval"
    assert after["decided_by"] is None
    assert after["decision_at"] is None
    assert after["decision_reason"] is None
    assert after["audit_log"] == before["audit_log"]

    with database.get_connection() as connection:
        head = connection.execute(
            """
            SELECT event_count, final_hash
            FROM response_audit_chain_heads
            WHERE response_id = ?
            """,
            (response_id,),
        ).fetchone()

    assert head["event_count"] == 1
    assert head["final_hash"] == before["audit_log"][-1]["event_hash"]


def test_simulation_rolls_back_when_checkpoint_intent_preparation_fails(
    isolated_database,
    monkeypatch,
):
    from app.response import repository

    response_id = create_response()
    assert approve_response(response_id) == "updated"
    before = get_record(response_id)

    def fail_intent_preparation(connection, response_id):
        raise OSError("Simulated checkpoint-intent preparation failure.")

    monkeypatch.setattr(
        repository,
        "_prepare_audit_checkpoint_intent",
        fail_intent_preparation,
    )

    with pytest.raises(
        OSError,
        match="Simulated checkpoint-intent preparation failure",
    ):
        with database.get_connection() as connection:
            simulate_response(
                connection=connection,
                response_id=response_id,
                actor_id="analyst-alpha",
            )

    after = get_record(response_id)

    assert after["status"] == "approved"
    assert after["simulated"] is False
    assert after["executed"] is False
    assert after["audit_log"] == before["audit_log"]

    with database.get_connection() as connection:
        head = connection.execute(
            """
            SELECT event_count, final_hash
            FROM response_audit_chain_heads
            WHERE response_id = ?
            """,
            (response_id,),
        ).fetchone()

    assert head["event_count"] == 2
    assert head["final_hash"] == before["audit_log"][-1]["event_hash"]


def test_decision_rolls_back_when_database_state_update_fails(
    isolated_database,
):
    import sqlite3

    response_id = create_response()
    before = get_record(response_id)

    with database.get_connection() as connection:
        connection.execute(
            """
            CREATE TRIGGER reject_response_approval
            BEFORE UPDATE ON response_records
            WHEN OLD.id = NEW.id
             AND NEW.status = 'approved'
            BEGIN
                SELECT RAISE(ABORT, 'Simulated response state update failure.');
            END
            """
        )
        connection.commit()

    with pytest.raises(
        sqlite3.IntegrityError,
        match="Simulated response state update failure",
    ):
        with database.get_connection() as connection:
            decide_response(
                connection=connection,
                response_id=response_id,
                actor_id="approver-beta",
                decision="approved",
                reason="Must roll back if the database rejects the update.",
            )

    after = get_record(response_id)

    assert after["status"] == "pending_approval"
    assert after["decided_by"] is None
    assert after["decision_at"] is None
    assert after["decision_reason"] is None
    assert after["audit_log"] == before["audit_log"]

    with database.get_connection() as connection:
        head = connection.execute(
            """
            SELECT event_count, final_hash
            FROM response_audit_chain_heads
            WHERE response_id = ?
            """,
            (response_id,),
        ).fetchone()

    assert head["event_count"] == 1
    assert head["final_hash"] == before["audit_log"][-1]["event_hash"]


def test_simulation_rolls_back_when_database_state_update_fails(
    isolated_database,
):
    import sqlite3

    response_id = create_response()
    assert approve_response(response_id) == "updated"
    before = get_record(response_id)

    with database.get_connection() as connection:
        connection.execute(
            """
            CREATE TRIGGER reject_response_simulation
            BEFORE UPDATE ON response_records
            WHEN OLD.id = NEW.id
             AND NEW.status = 'simulated'
            BEGIN
                SELECT RAISE(ABORT, 'Simulated response state update failure.');
            END
            """
        )
        connection.commit()

    with pytest.raises(
        sqlite3.IntegrityError,
        match="Simulated response state update failure",
    ):
        with database.get_connection() as connection:
            simulate_response(
                connection=connection,
                response_id=response_id,
                actor_id="analyst-alpha",
            )

    after = get_record(response_id)

    assert after["status"] == "approved"
    assert after["simulated"] is False
    assert after["executed"] is False
    assert after["audit_log"] == before["audit_log"]

    with database.get_connection() as connection:
        head = connection.execute(
            """
            SELECT event_count, final_hash
            FROM response_audit_chain_heads
            WHERE response_id = ?
            """,
            (response_id,),
        ).fetchone()

    assert head["event_count"] == 2
    assert head["final_hash"] == before["audit_log"][-1]["event_hash"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("action", "delete_file"),
        ("target", "1.1.1.1"),
        ("requested_by", "attacker-account"),
        ("alert_id", None),
    ],
)
def test_tampered_response_identity_fields_block_simulation_without_mutation(
    isolated_database,
    field,
    value,
):
    response_id = create_response()
    assert approve_response(response_id) == "updated"
    before = get_record(response_id)

    with database.get_connection() as connection:
        if field == "alert_id":
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
                    "Alternate Audit Integrity Test",
                    "medium",
                    "Alternate alert for foreign-key-safe tampering test",
                    "1.1.1.1",
                    "AEGIS-AUTH-002",
                    "2026-11-06T10:05:00+00:00",
                    "open",
                ),
            )
            value = cursor.lastrowid

        connection.execute(
            f"UPDATE response_records SET {field} = ? WHERE id = ?",
            (value, response_id),
        )
        connection.commit()

    with database.get_connection() as connection:
        outcome = simulate_response(
            connection=connection,
            response_id=response_id,
            actor_id="analyst-alpha",
        )

    assert outcome == "audit_integrity_failure"

    after = get_record(response_id)
    assert after["status"] == "approved"
    assert after["simulated"] is False
    assert after["executed"] is False
    assert after["audit_log"] == before["audit_log"]

    integrity = validate_response_audit(after)
    assert integrity["valid"] is False
    assert integrity["errors"]


@pytest.mark.parametrize(
    "stored_reasons",
    [
        '{"unexpected":"object"}',
        '"unexpected scalar"',
        'not-json',
    ],
)
def test_invalid_persisted_response_reasons_block_simulation_and_remain_inspectable(
    isolated_database,
    stored_reasons,
):
    response_id = create_response()
    assert approve_response(response_id) == "updated"

    with database.get_connection() as connection:
        connection.execute(
            "UPDATE response_records SET reasons = ? WHERE id = ?",
            (stored_reasons, response_id),
        )
        connection.commit()

    with database.get_connection() as connection:
        outcome = simulate_response(
            connection=connection,
            response_id=response_id,
            actor_id="analyst-alpha",
        )

    assert outcome == "audit_integrity_failure"

    record = get_record(response_id)
    assert record["reasons"] == stored_reasons
    assert record["status"] == "approved"
    assert record["simulated"] is False
    assert record["executed"] is False

    with database.get_connection() as connection:
        history = get_response_history(connection)

    matching = next(item for item in history if item["id"] == response_id)
    assert matching["reasons"] == stored_reasons

