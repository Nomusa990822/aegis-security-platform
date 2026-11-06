
from app import database


ANALYST_TOKEN = "a" * 48
APPROVER_TOKEN = "b" * 48


def analyst_headers():
    return {"Authorization": f"Bearer {ANALYST_TOKEN}"}


def approver_headers():
    return {"Authorization": f"Bearer {APPROVER_TOKEN}"}


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
                "Lifecycle Audit Test Alert",
                "high",
                "Testing response lifecycle audit coverage",
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
        headers=analyst_headers(),
    )

    assert response.status_code == 201
    return response.json()["response_id"]


def inspect_audit(client, response_id):
    return client.get(
        f"/api/v1/response/{response_id}/audit-integrity",
        headers=approver_headers(),
    )


def get_audit_events(response_id):
    with database.get_connection() as connection:
        rows = connection.execute(
            """
            SELECT event
            FROM response_audit_log
            WHERE response_id = ?
            ORDER BY id ASC
            """,
            (response_id,),
        ).fetchall()

    return [row["event"] for row in rows]


def test_pending_approval_lifecycle_has_valid_audit(client):
    response_id = create_pending_response(client)

    response = inspect_audit(client, response_id)

    assert response.status_code == 200
    assert response.json()["status"] == "pending_approval"
    assert response.json()["valid"] is True
    assert response.json()["errors"] == []

    assert get_audit_events(response_id) == [
        "response_request_created",
    ]


def test_approved_lifecycle_has_valid_audit(client):
    response_id = create_pending_response(client)

    decision = client.post(
        f"/api/v1/response/{response_id}/approve",
        json={"reason": "Approved for lifecycle testing."},
        headers=approver_headers(),
    )

    assert decision.status_code == 200

    response = inspect_audit(client, response_id)

    assert response.status_code == 200
    assert response.json()["status"] == "approved"
    assert response.json()["valid"] is True
    assert response.json()["errors"] == []

    assert get_audit_events(response_id) == [
        "response_request_created",
        "response_approved",
    ]


def test_rejected_lifecycle_has_valid_audit(client):
    response_id = create_pending_response(client)

    decision = client.post(
        f"/api/v1/response/{response_id}/reject",
        json={"reason": "Rejected for lifecycle testing."},
        headers=approver_headers(),
    )

    assert decision.status_code == 200

    response = inspect_audit(client, response_id)

    assert response.status_code == 200
    assert response.json()["status"] == "rejected"
    assert response.json()["valid"] is True
    assert response.json()["errors"] == []

    assert get_audit_events(response_id) == [
        "response_request_created",
        "response_rejected",
    ]


def test_simulated_lifecycle_has_valid_audit(client):
    response_id = create_pending_response(client)

    approval = client.post(
        f"/api/v1/response/{response_id}/approve",
        json={"reason": "Approved for dry-run testing."},
        headers=approver_headers(),
    )

    assert approval.status_code == 200

    simulation = client.post(
        f"/api/v1/response/{response_id}/simulate",
        headers=analyst_headers(),
    )

    assert simulation.status_code == 200

    response = inspect_audit(client, response_id)

    assert response.status_code == 200
    assert response.json()["status"] == "simulated"
    assert response.json()["valid"] is True
    assert response.json()["errors"] == []

    assert get_audit_events(response_id) == [
        "response_request_created",
        "response_approved",
        "response_simulated",
    ]
