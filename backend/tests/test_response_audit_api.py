import json

from app import database


ANALYST_TOKEN = "a" * 48
APPROVER_TOKEN = "b" * 48


def analyst_headers():
    return {
        "Authorization": f"Bearer {ANALYST_TOKEN}",
    }


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
                "Audit API Test Alert",
                "high",
                "Testing the audit integrity API",
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


def approve_response(client, response_id):
    response = client.post(
        f"/api/v1/response/{response_id}/approve",
        json={
            "reason": "Approved for audit API testing.",
        },
        headers=approver_headers(),
    )

    assert response.status_code == 200


def get_audit_rows(response_id):
    with database.get_connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM response_audit_log
            WHERE response_id = ?
            ORDER BY id ASC
            """,
            (response_id,),
        ).fetchall()

    return [dict(row) for row in rows]


def test_audit_integrity_requires_authentication(client):
    response_id = create_pending_response(client)

    response = client.get(
        f"/api/v1/response/{response_id}/audit-integrity",
        headers={"Authorization": ""},
    )

    assert response.status_code == 401


def test_audit_integrity_rejects_analyst_role(client):
    response_id = create_pending_response(client)

    response = client.get(
        f"/api/v1/response/{response_id}/audit-integrity",
        headers=analyst_headers(),
    )

    assert response.status_code == 403


def test_audit_integrity_accepts_approver_role(client):
    response_id = create_pending_response(client)
    approve_response(client, response_id)

    response = client.get(
        f"/api/v1/response/{response_id}/audit-integrity",
        headers=approver_headers(),
    )

    assert response.status_code == 200
    assert response.json() == {
        "response_id": response_id,
        "status": "approved",
        "valid": True,
        "errors": [],
    }


def test_audit_integrity_detects_tampered_audit_actor(client):
    response_id = create_pending_response(client)
    approve_response(client, response_id)

    with database.get_connection() as connection:
        connection.execute(
            """
            UPDATE response_audit_log
            SET actor = ?
            WHERE response_id = ?
              AND event = ?
            """,
            (
                "unauthorised-user",
                response_id,
                "response_approved",
            ),
        )
        connection.commit()

    response = client.get(
        f"/api/v1/response/{response_id}/audit-integrity",
        headers=approver_headers(),
    )

    assert response.status_code == 200
    assert response.json()["valid"] is False
    assert any(
        "actor" in error.lower()
        for error in response.json()["errors"]
    )


def test_audit_integrity_returns_404_for_unknown_response(client):
    response = client.get(
        "/api/v1/response/999999/audit-integrity",
        headers=approver_headers(),
    )

    assert response.status_code == 404


def test_audit_integrity_rejects_non_positive_response_id(client):
    response = client.get(
        "/api/v1/response/0/audit-integrity",
        headers=approver_headers(),
    )

    assert response.status_code == 400


def test_audit_integrity_does_not_modify_audit_records(client):
    response_id = create_pending_response(client)
    approve_response(client, response_id)

    before = get_audit_rows(response_id)

    response = client.get(
        f"/api/v1/response/{response_id}/audit-integrity",
        headers=approver_headers(),
    )

    after = get_audit_rows(response_id)

    assert response.status_code == 200
    assert response.json()["valid"] is True
    assert before == after


def test_audit_integrity_detects_modified_audit_details(client):
    response_id = create_pending_response(client)
    approve_response(client, response_id)

    with database.get_connection() as connection:
        row = connection.execute(
            """
            SELECT id, details
            FROM response_audit_log
            WHERE response_id = ?
              AND event = ?
            """,
            (response_id, "response_approved"),
        ).fetchone()

        details = json.loads(row["details"])
        details["new_status"] = "simulated"

        connection.execute(
            """
            UPDATE response_audit_log
            SET details = ?
            WHERE id = ?
            """,
            (
                json.dumps(details),
                row["id"],
            ),
        )
        connection.commit()

    response = client.get(
        f"/api/v1/response/{response_id}/audit-integrity",
        headers=approver_headers(),
    )

    assert response.status_code == 200
    assert response.json()["valid"] is False
    assert response.json()["errors"]