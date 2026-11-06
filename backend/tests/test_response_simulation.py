
from app import database


APPROVER_TOKEN = "b" * 48


def approver_headers():
    return {
        "Authorization": f"Bearer {APPROVER_TOKEN}",
    }


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
                "Simulation Workflow Test Alert",
                "high",
                "Testing safe response simulation",
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


def approve_response(client, response_id):
    response = client.post(
        f"/api/v1/response/{response_id}/approve",
        json={
            "reason": "Approved for controlled dry-run testing.",
        },
        headers=approver_headers(),
    )

    assert response.status_code == 200
    assert response.json()["response"]["status"] == "approved"


def test_simulation_requires_authentication(client):
    response = client.post(
        "/api/v1/response/1/simulate",
        headers={"Authorization": ""},
    )

    assert response.status_code == 401


def test_approver_cannot_simulate_as_analyst(client):
    response_id = create_pending_response(client)
    approve_response(client, response_id)

    response = client.post(
        f"/api/v1/response/{response_id}/simulate",
        headers=approver_headers(),
    )

    assert response.status_code == 403


def test_pending_response_cannot_be_simulated(client):
    response_id = create_pending_response(client)

    response = client.post(
        f"/api/v1/response/{response_id}/simulate",
    )

    assert response.status_code == 409
    assert "Only approved" in response.json()["detail"]

    detail = client.get(
        f"/api/v1/response/history/{response_id}",
    )

    assert detail.status_code == 200
    assert detail.json()["status"] == "pending_approval"
    assert detail.json()["simulated"] is False
    assert len(detail.json()["audit_log"]) == 1


def test_rejected_response_cannot_be_simulated(client):
    response_id = create_pending_response(client)

    rejection = client.post(
        f"/api/v1/response/{response_id}/reject",
        json={
            "reason": "Not authorised.",
        },
        headers=approver_headers(),
    )

    assert rejection.status_code == 200
    assert rejection.json()["response"]["status"] == "rejected"

    response = client.post(
        f"/api/v1/response/{response_id}/simulate",
    )

    assert response.status_code == 409

    detail = client.get(
        f"/api/v1/response/history/{response_id}",
    )

    assert detail.json()["status"] == "rejected"
    assert detail.json()["simulated"] is False
    assert len(detail.json()["audit_log"]) == 2


def test_approved_response_can_be_simulated(client):
    response_id = create_pending_response(client)
    approve_response(client, response_id)

    response = client.post(
        f"/api/v1/response/{response_id}/simulate",
    )

    assert response.status_code == 200

    record = response.json()["response"]

    assert record["status"] == "simulated"
    assert record["simulated"] is True
    assert record["executed"] is False
    assert record["decided_by"] == "approver-beta"

    assert len(record["audit_log"]) == 3

    simulation_event = record["audit_log"][2]

    assert simulation_event["event"] == "response_simulated"
    assert simulation_event["actor"] == "analyst-alpha"

    details = simulation_event["details"]

    assert details["simulation_mode"] == "dry_run"
    assert details["action"] == "block_ip"
    assert details["target"] == "8.8.8.8"
    assert details["outcome"] == "would_block"
    assert details["firewall_modified"] is False
    assert details["network_modified"] is False
    assert details["operating_system_command_executed"] is False
    assert details["executed"] is False
    assert details["simulated"] is True


def test_simulation_is_persisted_in_response_history(client):
    response_id = create_pending_response(client)
    approve_response(client, response_id)

    simulation = client.post(
        f"/api/v1/response/{response_id}/simulate",
    )

    assert simulation.status_code == 200

    detail = client.get(
        f"/api/v1/response/history/{response_id}",
    )

    assert detail.status_code == 200

    record = detail.json()

    assert record["status"] == "simulated"
    assert record["simulated"] is True
    assert record["executed"] is False

    events = [
        item["event"]
        for item in record["audit_log"]
    ]

    assert events == [
        "response_request_created",
        "response_approved",
        "response_simulated",
    ]


def test_response_cannot_be_simulated_twice(client):
    response_id = create_pending_response(client)
    approve_response(client, response_id)

    first = client.post(
        f"/api/v1/response/{response_id}/simulate",
    )

    assert first.status_code == 200

    second = client.post(
        f"/api/v1/response/{response_id}/simulate",
    )

    assert second.status_code == 409

    detail = client.get(
        f"/api/v1/response/history/{response_id}",
    )

    assert detail.status_code == 200
    assert detail.json()["status"] == "simulated"
    assert detail.json()["simulated"] is True
    assert detail.json()["executed"] is False
    assert len(detail.json()["audit_log"]) == 3


def test_nonexistent_response_cannot_be_simulated(client):
    response = client.post(
        "/api/v1/response/999999/simulate",
    )

    assert response.status_code == 404


def test_simulation_rejects_non_positive_response_id(client):
    response = client.post(
        "/api/v1/response/0/simulate",
    )

    assert response.status_code == 400


def test_simulation_does_not_change_alert_or_network_state(client):
    response_id = create_pending_response(client)
    approve_response(client, response_id)

    before = client.get(
        f"/api/v1/response/history/{response_id}",
    )

    simulation = client.post(
        f"/api/v1/response/{response_id}/simulate",
    )

    assert simulation.status_code == 200

    after = client.get(
        f"/api/v1/response/history/{response_id}",
    )

    assert before.status_code == 200
    assert after.status_code == 200

    record = after.json()

    assert record["target"] == "8.8.8.8"
    assert record["executed"] is False
    assert record["simulated"] is True

    report = record["audit_log"][-1]["details"]

    assert report["firewall_modified"] is False
    assert report["network_modified"] is False
    assert report["operating_system_command_executed"] is False
