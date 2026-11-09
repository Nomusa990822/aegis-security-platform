
import threading
from concurrent.futures import ThreadPoolExecutor

from app import database
from app.response import repository
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
    verify_response_audit_before_mutation,
)


def create_pending_response():
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
                "Concurrent Response Test",
                "high",
                "Testing concurrent response operations",
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

        return save_response(
            connection,
            request,
            result,
        )


def run_concurrently(operation, arguments):
    barrier = threading.Barrier(len(arguments))

    def worker(argument):
        connection = database.get_connection()

        try:
            barrier.wait(timeout=10)
            return operation(connection, *argument)
        finally:
            connection.close()

    with ThreadPoolExecutor(
        max_workers=len(arguments)
    ) as executor:
        futures = [
            executor.submit(worker, argument)
            for argument in arguments
        ]

        return [
            future.result(timeout=15)
            for future in futures
        ]


def test_concurrent_approval_and_rejection_allow_only_one_decision(
    isolated_database,
):
    response_id = create_pending_response()

    outcomes = run_concurrently(
        lambda connection, actor_id, decision: decide_response(
            connection=connection,
            response_id=response_id,
            actor_id=actor_id,
            decision=decision,
            reason=f"Concurrent decision by {actor_id}",
        ),
        [
            ("approver-one", "approved"),
            ("approver-two", "rejected"),
        ],
    )

    assert outcomes.count("updated") == 1
    assert outcomes.count("already_decided") == 1

    with database.get_connection() as connection:
        record = get_response_record(
            connection,
            response_id,
        )

    assert record["status"] in {"approved", "rejected"}
    assert record["decided_by"] in {
        "approver-one",
        "approver-two",
    }

    assert record["executed"] is False
    assert record["simulated"] is False

    events = record["audit_log"]

    assert len(events) == 2
    assert events[0]["event"] == "response_request_created"

    decision_events = [
        event
        for event in events
        if event["event"] in {
            "response_approved",
            "response_rejected",
        }
    ]

    assert len(decision_events) == 1
    assert decision_events[0]["actor"] == record["decided_by"]

    assert decision_events[0]["event"] == (
        f"response_{record['status']}"
    )


def test_concurrent_simulation_runs_only_once(
    isolated_database,
):
    response_id = create_pending_response()

    with database.get_connection() as connection:
        approval = decide_response(
            connection=connection,
            response_id=response_id,
            actor_id="approver-beta",
            decision="approved",
            reason="Authorised for simulation.",
        )

    assert approval == "updated"

    outcomes = run_concurrently(
        lambda connection, actor_id: simulate_response(
            connection=connection,
            response_id=response_id,
            actor_id=actor_id,
        ),
        [
            ("analyst-one",),
            ("analyst-two",),
        ],
    )

    assert outcomes.count("simulated") == 1
    assert outcomes.count("already_simulated") == 1

    with database.get_connection() as connection:
        record = get_response_record(
            connection,
            response_id,
        )

    assert record["status"] == "simulated"
    assert record["simulated"] is True
    assert record["executed"] is False

    events = record["audit_log"]

    assert len(events) == 3

    assert [
        event["event"]
        for event in events
    ] == [
        "response_request_created",
        "response_approved",
        "response_simulated",
    ]

    simulation_events = [
        event
        for event in events
        if event["event"] == "response_simulated"
    ]

    assert len(simulation_events) == 1

    simulation = simulation_events[0]

    assert simulation["actor"] in {
        "analyst-one",
        "analyst-two",
    }

    details = simulation["details"]

    assert details["outcome"] == "would_block"
    assert details["firewall_modified"] is False
    assert details["network_modified"] is False
    assert details["operating_system_command_executed"] is False
    assert details["executed"] is False
    assert details["simulated"] is True


def test_simulation_retry_accepts_valid_pending_checkpoint_intent(
    isolated_database,
    monkeypatch,
):
    response_id = create_pending_response()

    with database.get_connection() as connection:
        approval = decide_response(
            connection=connection,
            response_id=response_id,
            actor_id="approver-beta",
            decision="approved",
            reason="Authorised for pending-checkpoint retry test.",
        )

    assert approval == "updated"

    original_publisher = repository._write_committed_audit_checkpoint
    monkeypatch.setattr(
        repository,
        "_write_committed_audit_checkpoint",
        lambda connection, response_id: False,
    )

    with database.get_connection() as connection:
        first_outcome = simulate_response(
            connection=connection,
            response_id=response_id,
            actor_id="analyst-one",
        )

    assert first_outcome == "checkpoint_pending"

    monkeypatch.setattr(
        repository,
        "_write_committed_audit_checkpoint",
        original_publisher,
    )

    with database.get_connection() as connection:
        retry_outcome = simulate_response(
            connection=connection,
            response_id=response_id,
            actor_id="analyst-two",
        )

    assert retry_outcome == "already_simulated"

    with database.get_connection() as connection:
        record = get_response_record(connection, response_id)

    assert record["status"] == "simulated"
    assert record["simulated"] is True
    assert record["executed"] is False
    assert len(record["audit_log"]) == 3


def test_concurrent_operations_preserve_audit_consistency(
    isolated_database,
):
    response_id = create_pending_response()

    outcomes = run_concurrently(
        lambda connection, actor_id, decision: decide_response(
            connection=connection,
            response_id=response_id,
            actor_id=actor_id,
            decision=decision,
            reason="Concurrent audit consistency test.",
        ),
        [
            ("approver-one", "approved"),
            ("approver-two", "rejected"),
        ],
    )

    assert outcomes.count("updated") == 1

    with database.get_connection() as connection:
        record = get_response_record(
            connection,
            response_id,
        )

        audit_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM response_audit_log
            WHERE response_id = ?
            """,
            (response_id,),
        ).fetchone()[0]

        foreign_key_errors = connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()

    assert audit_count == len(record["audit_log"])
    assert len(record["audit_log"]) == 2
    assert foreign_key_errors == []

    audit_ids = [
        event["id"]
        for event in record["audit_log"]
    ]

    assert audit_ids == sorted(audit_ids)
    assert len(audit_ids) == len(set(audit_ids))

    assert record["executed"] is False
    assert record["simulated"] is False

def test_concurrent_approval_and_simulation_preserve_valid_lifecycle(
    isolated_database,
):
    response_id = create_pending_response()

    outcomes = run_concurrently(
        lambda connection, operation, actor_id: (
            decide_response(
                connection=connection,
                response_id=response_id,
                actor_id=actor_id,
                decision="approved",
                reason="Concurrent approval/simulation test.",
            )
            if operation == "approve"
            else simulate_response(
                connection=connection,
                response_id=response_id,
                actor_id=actor_id,
            )
        ),
        [
            ("approve", "approver-gamma"),
            ("simulate", "analyst-gamma"),
        ],
    )

    approval_outcome, simulation_outcome = outcomes

    assert approval_outcome == "updated"
    assert simulation_outcome in {
        "not_approved",
        "audit_integrity_failure",
        "simulated",
    }

    with database.get_connection() as connection:
        record = get_response_record(
            connection,
            response_id,
        )

        connection.execute("BEGIN IMMEDIATE")
        integrity = verify_response_audit_before_mutation(
            connection,
            response_id,
        )
        connection.rollback()

    assert integrity["valid"] is True
    assert record["executed"] is False

    event_names = [
        event["event"]
        for event in record["audit_log"]
    ]

    assert event_names[:2] == [
        "response_request_created",
        "response_approved",
    ]

    if simulation_outcome == "simulated":
        assert record["status"] == "simulated"
        assert record["simulated"] is True
        assert event_names == [
            "response_request_created",
            "response_approved",
            "response_simulated",
        ]
    else:
        assert record["status"] == "approved"
        assert record["simulated"] is False
        assert event_names == [
            "response_request_created",
            "response_approved",
        ]

