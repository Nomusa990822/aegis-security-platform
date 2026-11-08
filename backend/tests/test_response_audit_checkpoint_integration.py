
import json
import os
from pathlib import Path

from app import database
from app.response.audit_chain import calculate_event_hash


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


def create_pending_response(client, expected_status=201):
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

    assert response.status_code == expected_status

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


def get_checkpoint_path(response_id):
    directory = Path(os.environ["AEGIS_AUDIT_CHECKPOINT_DIR"])
    return directory / f"response_{response_id}.json"


def get_checkpoint_intent_path(response_id):
    directory = Path(os.environ["AEGIS_AUDIT_CHECKPOINT_DIR"])
    return directory / f"response_{response_id}.pending.json"


def inspect_integrity(client, response_id):
    return client.get(
        f"/api/v1/response/{response_id}/audit-integrity",
        headers=approver_headers(),
    )


def test_request_creation_writes_signed_checkpoint(client):
    response_id = create_pending_response(client)

    result = inspect_integrity(client, response_id)

    assert result.status_code == 200
    assert result.json()["valid"] is True
    assert result.json()["chain_valid"] is True
    assert result.json()["checkpoint_valid"] is True
    assert result.json()["event_count"] == 1

    assert get_checkpoint_path(response_id).exists()


def test_approval_updates_signed_checkpoint(client):
    response_id = create_pending_response(client)

    approve_response(client, response_id)

    result = inspect_integrity(client, response_id)

    assert result.status_code == 200
    assert result.json()["valid"] is True
    assert result.json()["checkpoint_valid"] is True
    assert result.json()["event_count"] == 2

    document = json.loads(
        get_checkpoint_path(response_id).read_text()
    )

    assert document["payload"]["response_id"] == response_id
    assert document["payload"]["event_count"] == 2


def test_rejection_updates_signed_checkpoint(client):
    response_id = create_pending_response(client)

    rejection = client.post(
        f"/api/v1/response/{response_id}/reject",
        json={
            "reason": "Rejected during checkpoint integration testing.",
        },
        headers=approver_headers(),
    )

    assert rejection.status_code == 200
    assert rejection.json()["response"]["status"] == "rejected"

    result = inspect_integrity(client, response_id)

    assert result.status_code == 200
    assert result.json()["valid"] is True
    assert result.json()["chain_valid"] is True
    assert result.json()["checkpoint_valid"] is True
    assert result.json()["event_count"] == 2

    document = json.loads(
        get_checkpoint_path(response_id).read_text()
    )

    assert document["payload"]["event_count"] == 2


def test_simulation_updates_signed_checkpoint(client):
    response_id = create_pending_response(client)

    approve_response(client, response_id)

    simulation = client.post(
        f"/api/v1/response/{response_id}/simulate",
        headers=analyst_headers(),
    )

    assert simulation.status_code == 200
    assert simulation.json()["response"]["status"] == "simulated"

    result = inspect_integrity(client, response_id)

    assert result.status_code == 200
    assert result.json()["valid"] is True
    assert result.json()["chain_valid"] is True
    assert result.json()["checkpoint_valid"] is True
    assert result.json()["event_count"] == 3

    document = json.loads(
        get_checkpoint_path(response_id).read_text()
    )

    assert document["payload"]["event_count"] == 3


def test_missing_checkpoint_is_detected(client):
    response_id = create_pending_response(client)

    get_checkpoint_path(response_id).unlink()

    result = inspect_integrity(client, response_id)

    assert result.status_code == 200
    assert result.json()["valid"] is False
    assert result.json()["checkpoint_valid"] is False
    assert any(
        "checkpoint file is missing" in error.lower()
        for error in result.json()["errors"]
    )


def test_modified_checkpoint_signature_is_detected(client):
    response_id = create_pending_response(client)

    checkpoint_path = get_checkpoint_path(response_id)

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


def test_database_chain_and_head_tampering_is_detected(
    client,
):
    response_id = create_pending_response(client)

    checkpoint_path = get_checkpoint_path(response_id)
    original_checkpoint = json.loads(checkpoint_path.read_text())

    with database.get_connection() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM response_audit_log
            WHERE response_id = ?
            ORDER BY id ASC
            """,
            (response_id,),
        ).fetchone()

        assert row is not None

        event = dict(row)
        details = json.loads(event["details"])

        # Add a field that does not alter the legitimate lifecycle data.
        details["attacker_added_marker"] = "database_rewritten"
        event["details"] = details

        rewritten_hash = calculate_event_hash(
            event,
            event["previous_hash"],
        )

        connection.execute(
            """
            UPDATE response_audit_log
            SET details = ?, event_hash = ?
            WHERE id = ?
            """,
            (
                json.dumps(
                    details,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                rewritten_hash,
                event["id"],
            ),
        )

        # Simulate an attacker who also rewrites the SQLite chain head.
        connection.execute(
            """
            UPDATE response_audit_chain_heads
            SET final_hash = ?
            WHERE response_id = ?
            """,
            (rewritten_hash, response_id),
        )

        connection.commit()

    # The external signed checkpoint must remain unchanged.
    current_checkpoint = json.loads(checkpoint_path.read_text())
    assert current_checkpoint == original_checkpoint

    result = inspect_integrity(client, response_id)

    assert result.status_code == 200

    # The attacker has made the database chain internally consistent.
    assert result.json()["chain_valid"] is True

    # The original signed checkpoint must expose the rewritten database.
    assert result.json()["checkpoint_valid"] is False
    assert result.json()["valid"] is False

    assert any(
        "checkpoint final hash does not match" in error.lower()
        for error in result.json()["errors"]
    )


def test_checkpoint_write_failure_does_not_undo_committed_response(
    client,
    monkeypatch,
):
    from app.response import repository

    def fail_checkpoint_write(**kwargs):
        raise OSError("Simulated checkpoint storage failure.")

    monkeypatch.setattr(
        repository,
        "publish_checkpoint_intent",
        fail_checkpoint_write,
    )

    response_id = create_pending_response(
        client,
        expected_status=202,
    )

    # The database operation must remain committed.
    history = client.get(
        f"/api/v1/response/history/{response_id}",
        headers=analyst_headers(),
    )

    assert history.status_code == 200
    assert history.json()["status"] == "pending_approval"
    assert len(history.json()["audit_log"]) == 1

    # But integrity verification must report the missing checkpoint.
    result = inspect_integrity(client, response_id)

    assert result.status_code == 200
    assert result.json()["valid"] is False
    assert result.json()["chain_valid"] is True
    assert result.json()["checkpoint_valid"] is False

    assert any(
        "checkpoint file is missing" in error.lower()
        for error in result.json()["errors"]
    )

    # The signed pre-commit intent is retained for explicit recovery.
    assert get_checkpoint_intent_path(response_id).exists()


def test_missing_checkpoint_blocks_approval_without_mutation(
    client,
):
    response_id = create_pending_response(client)
    checkpoint_path = get_checkpoint_path(response_id)

    checkpoint_path.unlink()

    approval = client.post(
        f"/api/v1/response/{response_id}/approve",
        json={"reason": "Must fail closed."},
        headers=approver_headers(),
    )

    assert approval.status_code == 409
    assert "audit evidence failed integrity verification" in (
        approval.json()["detail"].lower()
    )
    assert not checkpoint_path.exists()

    history = client.get(
        f"/api/v1/response/history/{response_id}",
        headers=analyst_headers(),
    )
    assert history.status_code == 200
    assert history.json()["status"] == "pending_approval"
    assert history.json()["decided_by"] is None
    assert len(history.json()["audit_log"]) == 1

    result = inspect_integrity(client, response_id)
    assert result.status_code == 200
    assert result.json()["valid"] is False
    assert result.json()["checkpoint_valid"] is False


def test_tampered_checkpoint_blocks_approval_without_mutation(
    client,
):
    response_id = create_pending_response(client)
    checkpoint_path = get_checkpoint_path(response_id)

    original_document = json.loads(checkpoint_path.read_text())
    tampered_document = json.loads(json.dumps(original_document))
    tampered_document["signature"] = "0" * 64

    checkpoint_path.write_text(json.dumps(tampered_document))

    approval = client.post(
        f"/api/v1/response/{response_id}/approve",
        json={"reason": "Must fail closed."},
        headers=approver_headers(),
    )

    assert approval.status_code == 409
    assert json.loads(checkpoint_path.read_text()) == tampered_document

    history = client.get(
        f"/api/v1/response/history/{response_id}",
        headers=analyst_headers(),
    )
    assert history.status_code == 200
    assert history.json()["status"] == "pending_approval"
    assert history.json()["decided_by"] is None
    assert len(history.json()["audit_log"]) == 1

    result = inspect_integrity(client, response_id)
    assert result.status_code == 200
    assert result.json()["valid"] is False
    assert result.json()["checkpoint_valid"] is False



def test_database_tampering_before_checkpoint_advancement_is_detected(
    client,
):
    response_id = create_pending_response(client)
    checkpoint_path = get_checkpoint_path(response_id)

    original_checkpoint = json.loads(
        checkpoint_path.read_text()
    )

    # Rewrite the existing database event and its hash.
    with database.get_connection() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM response_audit_log
            WHERE response_id = ?
            ORDER BY id ASC
            LIMIT 1
            """,
            (response_id,),
        ).fetchone()

        assert row is not None

        event = dict(row)
        details = json.loads(event["details"])
        details["attacker_added_marker"] = "modified_before_approval"

        event["details"] = details

        rewritten_hash = calculate_event_hash(
            event,
            event["previous_hash"],
        )

        connection.execute(
            """
            UPDATE response_audit_log
            SET details = ?, event_hash = ?
            WHERE id = ?
            """,
            (
                json.dumps(
                    details,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                rewritten_hash,
                event["id"],
            ),
        )

        connection.execute(
            """
            UPDATE response_audit_chain_heads
            SET final_hash = ?
            WHERE response_id = ?
            """,
            (rewritten_hash, response_id),
        )

        connection.commit()

    # The database has been rewritten, but the external checkpoint
    # still contains the original trusted hash.
    approval = client.post(
        f"/api/v1/response/{response_id}/approve",
        json={"reason": "Must fail closed."},
        headers=approver_headers(),
    )
    assert approval.status_code == 409

    current_checkpoint = json.loads(checkpoint_path.read_text())

    # The failed operation must neither advance the checkpoint nor mutate
    # the response lifecycle.
    assert current_checkpoint == original_checkpoint

    history = client.get(
        f"/api/v1/response/history/{response_id}",
        headers=analyst_headers(),
    )
    assert history.status_code == 200
    assert history.json()["status"] == "pending_approval"
    assert history.json()["decided_by"] is None
    assert len(history.json()["audit_log"]) == 1

    result = inspect_integrity(client, response_id)

    assert result.status_code == 200
    assert result.json()["valid"] is False
    assert result.json()["chain_valid"] is True
    assert result.json()["checkpoint_valid"] is False

    assert any(
        "checkpoint final hash does not match" in error.lower()
        for error in result.json()["errors"]
    )


def test_api_verifies_old_checkpoint_and_advances_with_new_key(
    client,
    monkeypatch,
):
    old_secret = os.environ["AEGIS_AUDIT_CHECKPOINT_KEY"]

    monkeypatch.setenv(
        "AEGIS_AUDIT_CHECKPOINT_KEY_ID",
        "key-v1",
    )

    response_id = create_pending_response(client)

    checkpoint_path = get_checkpoint_path(response_id)
    original_document = json.loads(checkpoint_path.read_text())

    assert original_document["payload"]["key_id"] == "key-v1"

    new_secret = "api-rotation-checkpoint-secret-" + ("y" * 32)

    monkeypatch.setenv(
        "AEGIS_AUDIT_CHECKPOINT_KEY",
        new_secret,
    )
    monkeypatch.setenv(
        "AEGIS_AUDIT_CHECKPOINT_KEY_ID",
        "key-v2",
    )
    monkeypatch.setenv(
        "AEGIS_AUDIT_CHECKPOINT_PREVIOUS_KEYS",
        json.dumps({"key-v1": old_secret}),
    )

    old_checkpoint_result = inspect_integrity(client, response_id)

    assert old_checkpoint_result.status_code == 200
    assert old_checkpoint_result.json()["valid"] is True
    assert old_checkpoint_result.json()["checkpoint_valid"] is True

    approve_response(client, response_id)

    updated_document = json.loads(checkpoint_path.read_text())

    assert updated_document["payload"]["key_id"] == "key-v2"
    assert updated_document["payload"]["event_count"] == 2

    updated_result = inspect_integrity(client, response_id)

    assert updated_result.status_code == 200
    assert updated_result.json()["valid"] is True
    assert updated_result.json()["chain_valid"] is True
    assert updated_result.json()["checkpoint_valid"] is True


def test_api_rejects_old_checkpoint_when_previous_key_is_unavailable(
    client,
    monkeypatch,
):
    monkeypatch.setenv(
        "AEGIS_AUDIT_CHECKPOINT_KEY_ID",
        "key-v1",
    )

    response_id = create_pending_response(client)

    new_secret = "api-rotation-checkpoint-secret-" + ("z" * 32)

    monkeypatch.setenv(
        "AEGIS_AUDIT_CHECKPOINT_KEY",
        new_secret,
    )
    monkeypatch.setenv(
        "AEGIS_AUDIT_CHECKPOINT_KEY_ID",
        "key-v2",
    )
    monkeypatch.setenv(
        "AEGIS_AUDIT_CHECKPOINT_PREVIOUS_KEYS",
        "{}",
    )

    result = inspect_integrity(client, response_id)

    assert result.status_code == 200
    assert result.json()["valid"] is False
    assert result.json()["chain_valid"] is True
    assert result.json()["checkpoint_valid"] is False

    assert any(
        "not available" in error.lower()
        for error in result.json()["errors"]
    )


def test_api_key_rotation_integrity_inspection_is_read_only(
    client,
    monkeypatch,
):
    old_secret = os.environ["AEGIS_AUDIT_CHECKPOINT_KEY"]

    monkeypatch.setenv(
        "AEGIS_AUDIT_CHECKPOINT_KEY_ID",
        "key-v1",
    )

    response_id = create_pending_response(client)

    new_secret = "api-readonly-checkpoint-secret-" + ("q" * 32)

    monkeypatch.setenv(
        "AEGIS_AUDIT_CHECKPOINT_KEY",
        new_secret,
    )
    monkeypatch.setenv(
        "AEGIS_AUDIT_CHECKPOINT_KEY_ID",
        "key-v2",
    )
    monkeypatch.setenv(
        "AEGIS_AUDIT_CHECKPOINT_PREVIOUS_KEYS",
        json.dumps({"key-v1": old_secret}),
    )

    checkpoint_path = get_checkpoint_path(response_id)
    original_checkpoint = checkpoint_path.read_bytes()

    with database.get_connection() as connection:
        original_events = [
            dict(row)
            for row in connection.execute(
                """
                SELECT *
                FROM response_audit_log
                WHERE response_id = ?
                ORDER BY id ASC
                """,
                (response_id,),
            ).fetchall()
        ]

        original_head = dict(
            connection.execute(
                """
                SELECT *
                FROM response_audit_chain_heads
                WHERE response_id = ?
                """,
                (response_id,),
            ).fetchone()
        )

    result = inspect_integrity(client, response_id)

    assert result.status_code == 200
    assert result.json()["valid"] is True

    assert checkpoint_path.read_bytes() == original_checkpoint

    with database.get_connection() as connection:
        current_events = [
            dict(row)
            for row in connection.execute(
                """
                SELECT *
                FROM response_audit_log
                WHERE response_id = ?
                ORDER BY id ASC
                """,
                (response_id,),
            ).fetchall()
        ]

        current_head = dict(
            connection.execute(
                """
                SELECT *
                FROM response_audit_chain_heads
                WHERE response_id = ?
                """,
                (response_id,),
            ).fetchone()
        )

    assert current_events == original_events
    assert current_head == original_head


def test_missing_checkpoint_blocks_simulation_without_mutation(
    client,
):
    response_id = create_pending_response(client)
    approve_response(client, response_id)

    checkpoint_path = get_checkpoint_path(response_id)
    checkpoint_path.unlink()

    simulation = client.post(
        f"/api/v1/response/{response_id}/simulate",
        headers=analyst_headers(),
    )

    assert simulation.status_code == 409
    assert "audit evidence failed integrity verification" in (
        simulation.json()["detail"].lower()
    )
    assert not checkpoint_path.exists()

    history = client.get(
        f"/api/v1/response/history/{response_id}",
        headers=analyst_headers(),
    )
    assert history.status_code == 200
    assert history.json()["status"] == "approved"
    assert history.json()["simulated"] is False
    assert len(history.json()["audit_log"]) == 2


def test_hash_chain_tampering_blocks_approval_without_mutation(
    client,
):
    response_id = create_pending_response(client)

    with database.get_connection() as connection:
        connection.execute(
            """
            UPDATE response_audit_log
            SET actor = ?
            WHERE response_id = ?
            """,
            ("tampered-actor", response_id),
        )
        connection.commit()

    approval = client.post(
        f"/api/v1/response/{response_id}/approve",
        json={"reason": "Must fail closed."},
        headers=approver_headers(),
    )

    assert approval.status_code == 409

    history = client.get(
        f"/api/v1/response/history/{response_id}",
        headers=analyst_headers(),
    )
    assert history.status_code == 200
    assert history.json()["status"] == "pending_approval"
    assert history.json()["decided_by"] is None
    assert len(history.json()["audit_log"]) == 1




def test_approval_reports_committed_checkpoint_failure(
    client,
    monkeypatch,
):
    from app.response import repository

    response_id = create_pending_response(client)

    def fail_checkpoint_write(**kwargs):
        raise OSError("Simulated approval checkpoint storage failure.")

    monkeypatch.setattr(
        repository,
        "publish_checkpoint_intent",
        fail_checkpoint_write,
    )

    approval = client.post(
        f"/api/v1/response/{response_id}/approve",
        json={"reason": "Checkpoint failure reporting test."},
        headers=approver_headers(),
    )

    assert approval.status_code == 202
    assert approval.json()["committed"] is True
    assert approval.json()["checkpoint_status"] == "pending"

    history = client.get(
        f"/api/v1/response/history/{response_id}",
        headers=analyst_headers(),
    )
    assert history.status_code == 200
    assert history.json()["status"] == "approved"
    assert len(history.json()["audit_log"]) == 2

    integrity = inspect_integrity(client, response_id)
    assert integrity.status_code == 200
    assert integrity.json()["valid"] is False
    assert integrity.json()["checkpoint_valid"] is False
    assert get_checkpoint_intent_path(response_id).exists()


def test_simulation_reports_committed_checkpoint_failure(
    client,
    monkeypatch,
):
    from app.response import repository

    response_id = create_pending_response(client)
    approve_response(client, response_id)

    def fail_checkpoint_write(**kwargs):
        raise OSError("Simulated simulation checkpoint storage failure.")

    monkeypatch.setattr(
        repository,
        "publish_checkpoint_intent",
        fail_checkpoint_write,
    )

    simulation = client.post(
        f"/api/v1/response/{response_id}/simulate",
        headers=analyst_headers(),
    )

    assert simulation.status_code == 202
    assert simulation.json()["committed"] is True
    assert simulation.json()["checkpoint_status"] == "pending"

    history = client.get(
        f"/api/v1/response/history/{response_id}",
        headers=analyst_headers(),
    )
    assert history.status_code == 200
    assert history.json()["status"] == "simulated"
    assert history.json()["simulated"] is True
    assert len(history.json()["audit_log"]) == 3

    integrity = inspect_integrity(client, response_id)
    assert integrity.status_code == 200
    assert integrity.json()["valid"] is False
    assert integrity.json()["checkpoint_valid"] is False
    assert get_checkpoint_intent_path(response_id).exists()
