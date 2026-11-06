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
                "Checkpoint Integration Alert",
                "high",
                "Testing signed audit checkpoints",
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
            "reason": "Checkpoint integration test approval.",
        },
        headers=approver_headers(),
    )

    assert response.status_code == 200


def get_checkpoint_path(monkeypatch, response_id):
    from pathlib import Path
    import os

    directory = Path(os.environ["AEGIS_AUDIT_CHECKPOINT_DIR"])
    return directory / f"response_{response_id}.json"


def inspect_integrity(client, response_id):
    return client.get(
        f"/api/v1/response/{response_id}/audit-integrity",
        headers=approver_headers(),
    )


def test_request_creation_writes_signed_checkpoint(
    client,
    monkeypatch,
):
    response_id = create_pending_response(client)

    result = inspect_integrity(client, response_id)

    assert result.status_code == 200
    assert result.json()["valid"] is True
    assert result.json()["chain_valid"] is True
    assert result.json()["checkpoint_valid"] is True
    assert result.json()["event_count"] == 1

    checkpoint_path = get_checkpoint_path(
        monkeypatch,
        response_id,
    )

    assert checkpoint_path.exists()


def test_approval_updates_signed_checkpoint(
    client,
    monkeypatch,
):
    response_id = create_pending_response(client)

    approve_response(client, response_id)

    result = inspect_integrity(client, response_id)

    assert result.status_code == 200
    assert result.json()["valid"] is True
    assert result.json()["checkpoint_valid"] is True
    assert result.json()["event_count"] == 2

    checkpoint_path = get_checkpoint_path(
        monkeypatch,
        response_id,
    )

    document = json.loads(checkpoint_path.read_text())

    assert document["payload"]["response_id"] == response_id
    assert document["payload"]["event_count"] == 2


def test_missing_checkpoint_is_detected(
    client,
    monkeypatch,
):
    response_id = create_pending_response(client)

    checkpoint_path = get_checkpoint_path(
        monkeypatch,
        response_id,
    )

    checkpoint_path.unlink()

    result = inspect_integrity(client, response_id)

    assert result.status_code == 200
    assert result.json()["valid"] is False
    assert result.json()["checkpoint_valid"] is False
    assert any(
        "checkpoint file is missing" in error.lower()
        for error in result.json()["errors"]
    )


def test_modified_checkpoint_signature_is_detected(
    client,
    monkeypatch,
):
    response_id = create_pending_response(client)

    checkpoint_path = get_checkpoint_path(
        monkeypatch,
        response_id,
    )

    document = json.loads(checkpoint_path.read_text())
    document["payload"]["event_count"] = 999

    checkpoint_path.write_text(json.dumps(document))

    result = inspect_integrity(client, response_id)

    assert result.status_code == 200
    assert result.json()["valid"] is False
    assert result.json()["checkpoint_valid"] is False
    assert any(
        "signature is invalid" in error.lower()
        for error in result.json()["errors"]
    )