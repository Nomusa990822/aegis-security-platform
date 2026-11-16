
import pytest

from app import database


def create_pending_response(client):
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
                "Approval Workflow Test Alert",
                "high",
                "Testing approval workflow",
                "8.8.8.8",
                "AEGIS-AUTH-001",
                "2026-11-06T10:00:00+00:00",
                "open",
            ),
        )

        alert_id = cursor.lastrowid
        connection.commit()

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


def test_analyst_cannot_approve_response(client):
    response_id = create_pending_response(client)

    response = client.post(
        f"/api/v1/response/{response_id}/approve",
        json={},
    )

    assert response.status_code == 403


def test_analyst_cannot_reject_response(client):
    response_id = create_pending_response(client)

    response = approver_client.post(
        f"/api/v1/response/{response_id}/reject",
        json={},
    )

    assert response.status_code == 403


def test_approver_can_approve_pending_response(client, approver_client, approver_id):
    response_id = create_pending_response(client)

    response = approver_client.post(
        f"/api/v1/response/{response_id}/approve",
        json={
            "reason": "Reviewed and authorised.",
        },
    )

    assert response.status_code == 200

    record = response.json()["response"]

    assert record["status"] == "approved"
    assert record["decided_by"] == approver_id
    assert record["decision_at"] is not None
    assert record["decision_reason"] == "Reviewed and authorised."
    assert record["executed"] is False
    assert record["simulated"] is False

    assert len(record["audit_log"]) == 2

    decision_event = record["audit_log"][1]

    assert decision_event["event"] == "response_approved"
    assert decision_event["actor"] == approver_id
    assert decision_event["details"]["new_status"] == "approved"
    assert decision_event["details"]["executed"] is False
    assert decision_event["details"]["simulated"] is False


def test_approver_can_reject_pending_response(client, approver_client, approver_id):
    response_id = create_pending_response(client)

    response = approver_client.post(
        f"/api/v1/response/{response_id}/reject",
        json={
            "reason": "Insufficient justification.",
        },
    )

    assert response.status_code == 200

    record = response.json()["response"]

    assert record["status"] == "rejected"
    assert record["decided_by"] == "approver-beta"
    assert record["decision_at"] is not None
    assert record["decision_reason"] == "Insufficient justification."
    assert record["executed"] is False
    assert record["simulated"] is False

    assert len(record["audit_log"]) == 2

    decision_event = record["audit_log"][1]

    assert decision_event["event"] == "response_rejected"
    assert decision_event["actor"] == "approver-beta"


def test_requester_cannot_approve_own_response(client, approver_client, approver_id):
    response_id = create_pending_response(client)

    # Simulate a record requested by the approver identity.
    with database.get_connection() as connection:
        connection.execute(
            """
            UPDATE response_records
            SET requested_by = ?
            WHERE id = ?
            """,
            ("approver-beta", response_id),
        )
        connection.commit()

    response = approver_client.post(
        f"/api/v1/response/{response_id}/approve",
        json={},
    )

    assert response.status_code == 403

    detail = client.get(
        f"/api/v1/response/history/{response_id}",
    )

    assert detail.status_code == 200
    assert detail.json()["status"] == "pending_approval"
    assert len(detail.json()["audit_log"]) == 1


def test_requester_cannot_reject_own_response(client, approver_client, approver_id):
    response_id = create_pending_response(client)

    with database.get_connection() as connection:
        connection.execute(
            """
            UPDATE response_records
            SET requested_by = ?
            WHERE id = ?
            """,
            ("approver-beta", response_id),
        )
        connection.commit()

    response = client.post(
        f"/api/v1/response/{response_id}/reject",
        json={},
    )

    assert response.status_code == 403


def test_response_cannot_be_approved_twice(client, approver_client):
    response_id = create_pending_response(client)

    first = approver_client.post(
        f"/api/v1/response/{response_id}/approve",
        json={},
    )

    assert first.status_code == 200

    second = approver_client.post(
        f"/api/v1/response/{response_id}/approve",
        json={},
    )

    assert second.status_code == 409


def test_approved_response_cannot_later_be_rejected(client, approver_client):
    response_id = create_pending_response(client)

    approved = approver_client.post(
        f"/api/v1/response/{response_id}/approve",
        json={},
    )

    assert approved.status_code == 200

    rejected = approver_client.post(
        f"/api/v1/response/{response_id}/reject",
        json={},
    )

    assert rejected.status_code == 409


def test_rejected_response_cannot_later_be_approved(client, approver_client):
    response_id = create_pending_response(client)

    rejected = approver_client.post(
        f"/api/v1/response/{response_id}/reject",
        json={},
    )

    assert rejected.status_code == 200

    approved = approver_client.post(
        f"/api/v1/response/{response_id}/approve",
        json={},
    )

    assert approved.status_code == 409


def test_nonexistent_response_cannot_be_approved(approver_client):
    response = approver_client.post(
        "/api/v1/response/999999/approve",
        json={},
    )

    assert response.status_code == 404


def test_nonexistent_response_cannot_be_rejected(approver_client):
    response = approver_client.post(
        "/api/v1/response/999999/reject",
        json={},
    )

    assert response.status_code == 404


def test_approval_rejects_client_supplied_decision_identity(client, approver_client):
    response_id = create_pending_response(client)

    response = approver_client.post(
        f"/api/v1/response/{response_id}/approve",
        json={
            "reason": "Approved.",
            "decided_by": "fake-approver",
        },
    )

    assert response.status_code == 422

    detail = client.get(
        f"/api/v1/response/history/{response_id}",
    )

    assert detail.status_code == 200
    assert detail.json()["status"] == "pending_approval"
    assert detail.json()["decided_by"] is None
    assert len(detail.json()["audit_log"]) == 1


def test_approval_does_not_execute_or_simulate_response(client, approver_client):
    response_id = create_pending_response(client)

    response = approver_client.post(
        f"/api/v1/response/{response_id}/approve",
        json={},
    )

    assert response.status_code == 200

    record = response.json()["response"]

    assert record["status"] == "approved"
    assert record["executed"] is False
    assert record["simulated"] is False
