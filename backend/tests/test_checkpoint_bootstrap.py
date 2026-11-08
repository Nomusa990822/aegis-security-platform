import json
import os
import sqlite3
from pathlib import Path

from app import database
from app.response.checkpoint_bootstrap import (
    bootstrap_audit_checkpoints,
)


ANALYST_TOKEN = "a" * 48


def _create_response(client, expected_status=201):
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
                "Checkpoint Bootstrap Test Alert",
                "high",
                "Testing initial checkpoint bootstrap",
                "198.51.100.80",
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
            "target": "198.51.100.80",
        },
        headers={
            "Authorization": f"Bearer {ANALYST_TOKEN}",
        },
    )

    assert response.status_code == expected_status
    return response.json()["response_id"]


def _read_only_connection():
    database_path = Path(database.DATABASE_PATH).resolve()
    connection = sqlite3.connect(
        f"{database_path.as_uri()}?mode=ro",
        uri=True,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    return connection


def _checkpoint_path(response_id):
    return (
        Path(os.environ["AEGIS_AUDIT_CHECKPOINT_DIR"])
        / f"response_{response_id}.json"
    )


def test_bootstrap_defaults_to_dry_run_without_creating_checkpoint(client):
    response_id = _create_response(client)
    checkpoint = _checkpoint_path(response_id)
    checkpoint.unlink()

    with _read_only_connection() as connection:
        report = bootstrap_audit_checkpoints(
            connection,
            Path(os.environ["AEGIS_AUDIT_CHECKPOINT_DIR"]),
        )

    assert report["mode"] == "dry_run"
    assert report["eligible_response_ids"] == [response_id]
    assert report["planned_response_ids"] == [response_id]
    assert report["created_response_ids"] == []
    assert not checkpoint.exists()


def test_bootstrap_apply_creates_and_verifies_initial_checkpoint(client):
    response_id = _create_response(client)
    checkpoint = _checkpoint_path(response_id)
    checkpoint.unlink()

    with _read_only_connection() as connection:
        report = bootstrap_audit_checkpoints(
            connection,
            Path(os.environ["AEGIS_AUDIT_CHECKPOINT_DIR"]),
            apply=True,
        )

    assert report["mode"] == "apply"
    assert report["created_response_ids"] == [response_id]
    assert report["errors"] == []
    assert checkpoint.is_file()

    document = json.loads(checkpoint.read_text(encoding="utf-8"))
    assert document["payload"]["schema_version"] == 2
    assert document["payload"]["response_id"] == response_id
    assert document["payload"]["key_id"] == os.environ.get(
        "AEGIS_AUDIT_CHECKPOINT_KEY_ID",
        "default",
    )

    inspected = next(
        item
        for item in report["post_write_inventory"]["responses"]
        if item["response_id"] == response_id
    )
    assert inspected["checkpoint_signature_valid"] is True
    assert inspected["checkpoint_matches_database"] is True
    assert inspected["lifecycle_valid"] is True
    assert inspected["hash_chain_valid"] is True
    assert inspected["chain_head_matches"] is True


def test_bootstrap_never_overwrites_existing_checkpoint(client):
    response_id = _create_response(client)
    checkpoint = _checkpoint_path(response_id)
    original = checkpoint.read_bytes()

    with _read_only_connection() as connection:
        report = bootstrap_audit_checkpoints(
            connection,
            Path(os.environ["AEGIS_AUDIT_CHECKPOINT_DIR"]),
            apply=True,
        )

    assert response_id not in report["created_response_ids"]
    assert any(
        item["response_id"] == response_id
        for item in report["skipped"]
    )
    assert checkpoint.read_bytes() == original


def test_bootstrap_rejects_invalid_hash_chain(client):
    response_id = _create_response(client)
    checkpoint = _checkpoint_path(response_id)
    checkpoint.unlink()

    with database.get_connection() as connection:
        connection.execute(
            """
            UPDATE response_audit_log
            SET event_hash = ?
            WHERE response_id = ?
            """,
            ("0" * 64, response_id),
        )
        connection.commit()

    with _read_only_connection() as connection:
        report = bootstrap_audit_checkpoints(
            connection,
            Path(os.environ["AEGIS_AUDIT_CHECKPOINT_DIR"]),
            apply=True,
        )

    assert response_id not in report["created_response_ids"]
    assert not checkpoint.exists()
    skipped = next(
        item
        for item in report["skipped"]
        if item["response_id"] == response_id
    )
    assert skipped["reasons"]


def test_bootstrap_can_target_specific_response_ids(client):
    first_response_id = _create_response(client)
    second_response_id = _create_response(client)

    _checkpoint_path(first_response_id).unlink()
    _checkpoint_path(second_response_id).unlink()

    with _read_only_connection() as connection:
        report = bootstrap_audit_checkpoints(
            connection,
            Path(os.environ["AEGIS_AUDIT_CHECKPOINT_DIR"]),
            response_ids={second_response_id},
        )

    assert report["selected_response_ids"] == [second_response_id]
    assert report["eligible_response_ids"] == [second_response_id]
    assert first_response_id not in report["selected_response_ids"]



def test_bootstrap_does_not_bypass_a_pending_signed_intent(
    client,
    monkeypatch,
):
    from app.response import repository

    def fail_checkpoint_publication(**kwargs):
        raise OSError("Simulated checkpoint publication interruption.")

    monkeypatch.setattr(
        repository,
        "publish_checkpoint_intent",
        fail_checkpoint_publication,
    )

    response_id = _create_response(
        client,
        expected_status=202,
    )
    checkpoint = _checkpoint_path(response_id)
    intent = (
        Path(os.environ["AEGIS_AUDIT_CHECKPOINT_DIR"])
        / f"response_{response_id}.pending.json"
    )

    assert not checkpoint.exists()
    assert intent.exists()

    with _read_only_connection() as connection:
        report = bootstrap_audit_checkpoints(
            connection,
            Path(os.environ["AEGIS_AUDIT_CHECKPOINT_DIR"]),
            apply=True,
        )

    assert response_id not in report["created_response_ids"]
    assert not checkpoint.exists()
    skipped = next(
        item
        for item in report["skipped"]
        if item["response_id"] == response_id
    )
    assert any(
        "pending checkpoint intent" in reason.lower()
        for reason in skipped["reasons"]
    )
    assert intent.exists()


def test_stale_orphan_intent_is_dry_run_then_quarantined_with_evidence():
    import hashlib

    from app.response.checkpoint_intent import (
        checkpoint_intent_path,
        write_checkpoint_intent,
    )
    from app.response.checkpoint_intent_quarantine import (
        quarantine_stale_checkpoint_intents,
    )

    directory = Path(os.environ["AEGIS_AUDIT_CHECKPOINT_DIR"])
    with _read_only_connection() as connection:
        maximum = connection.execute(
            "SELECT COALESCE(MAX(id), 0) FROM response_records"
        ).fetchone()[0]
    response_id = maximum + 10000

    write_checkpoint_intent(
        response_id=response_id,
        event_count=1,
        final_hash="a" * 64,
        previous_event_count=0,
        previous_final_hash="0" * 64,
    )
    intent_path = checkpoint_intent_path(directory, response_id)
    original_bytes = intent_path.read_bytes()

    with _read_only_connection() as connection:
        dry_run = quarantine_stale_checkpoint_intents(
            connection,
            directory,
        )

    assert dry_run["eligible_response_ids"] == [response_id]
    assert dry_run["quarantined_response_ids"] == []
    assert intent_path.read_bytes() == original_bytes
    assert not (directory / "quarantine").exists()

    with _read_only_connection() as connection:
        applied = quarantine_stale_checkpoint_intents(
            connection,
            directory,
            apply=True,
            response_ids={response_id},
            reason="Verified orphan from an interrupted pre-commit transaction.",
        )

    assert applied["quarantined_response_ids"] == [response_id]
    assert not intent_path.exists()
    evidence = applied["evidence"][0]
    evidence_path = Path(evidence["intent_file"])
    manifest_path = Path(evidence["manifest_file"])
    assert evidence_path.read_bytes() == original_bytes
    assert evidence["sha256"] == hashlib.sha256(original_bytes).hexdigest()
    assert evidence_path.stat().st_mode & 0o777 == 0o600
    assert manifest_path.stat().st_mode & 0o777 == 0o600

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["response_id"] == response_id
    assert manifest["reason"].startswith("Verified orphan")
    assert manifest["sha256"] == evidence["sha256"]


def test_quarantine_refuses_intent_when_database_response_exists(
    client,
    monkeypatch,
):
    from app.response import repository
    from app.response.checkpoint_intent_quarantine import (
        quarantine_stale_checkpoint_intents,
    )

    def fail_publication(**kwargs):
        raise OSError("Simulated publication interruption.")

    monkeypatch.setattr(
        repository,
        "publish_checkpoint_intent",
        fail_publication,
    )
    response_id = _create_response(client, expected_status=202)
    directory = Path(os.environ["AEGIS_AUDIT_CHECKPOINT_DIR"])
    intent_path = directory / f"response_{response_id}.pending.json"
    original_bytes = intent_path.read_bytes()

    with _read_only_connection() as connection:
        report = quarantine_stale_checkpoint_intents(
            connection,
            directory,
            apply=True,
            response_ids={response_id},
            reason="This must be refused because the database has a response.",
        )

    assert report["quarantined_response_ids"] == []
    assert report["skipped"][0]["classification"] == "database_reference_exists"
    assert intent_path.read_bytes() == original_bytes


def test_quarantine_refuses_invalid_signed_intent():
    from app.response.checkpoint_intent import (
        checkpoint_intent_path,
        write_checkpoint_intent,
    )
    from app.response.checkpoint_intent_quarantine import (
        quarantine_stale_checkpoint_intents,
    )

    directory = Path(os.environ["AEGIS_AUDIT_CHECKPOINT_DIR"])
    with _read_only_connection() as connection:
        maximum = connection.execute(
            "SELECT COALESCE(MAX(id), 0) FROM response_records"
        ).fetchone()[0]
    response_id = maximum + 20000

    write_checkpoint_intent(
        response_id=response_id,
        event_count=1,
        final_hash="b" * 64,
        previous_event_count=0,
        previous_final_hash="0" * 64,
    )
    intent_path = checkpoint_intent_path(directory, response_id)
    document = json.loads(intent_path.read_text(encoding="utf-8"))
    document["signature"] = "0" * 64
    intent_path.write_text(json.dumps(document), encoding="utf-8")
    original_bytes = intent_path.read_bytes()

    with _read_only_connection() as connection:
        report = quarantine_stale_checkpoint_intents(
            connection,
            directory,
            apply=True,
            response_ids={response_id},
            reason="Invalid signatures must never be quarantined automatically.",
        )

    assert report["quarantined_response_ids"] == []
    assert report["skipped"][0]["classification"] == "intent_corrupt_or_unverifiable"
    assert intent_path.read_bytes() == original_bytes
