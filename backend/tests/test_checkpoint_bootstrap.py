import json
import os
import sqlite3
from pathlib import Path

from app import database
from app.response.checkpoint_bootstrap import (
    bootstrap_audit_checkpoints,
)


ANALYST_TOKEN = "a" * 48


def _create_response(client):
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

    assert response.status_code == 201
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
