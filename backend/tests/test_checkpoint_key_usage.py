import json
from pathlib import Path

from app.response.audit_checkpoint import (
    verify_audit_checkpoint,
    write_audit_checkpoint,
)
from app.response.checkpoint_intent import (
    checkpoint_intent_path,
    publish_checkpoint_intent,
    verify_checkpoint_intent,
    write_checkpoint_intent,
)
from app.response.checkpoint_key_usage import inspect_checkpoint_key_usage


OLD_SECRET = "aegis-key-rotation-old-secret-" + ("o" * 32)
NEW_SECRET = "aegis-key-rotation-new-secret-" + ("n" * 32)


def configure_old_key(monkeypatch, directory: Path):
    monkeypatch.setenv("AEGIS_AUDIT_CHECKPOINT_KEY", OLD_SECRET)
    monkeypatch.setenv("AEGIS_AUDIT_CHECKPOINT_KEY_ID", "key-v1")
    monkeypatch.setenv("AEGIS_AUDIT_CHECKPOINT_PREVIOUS_KEYS", "{}")
    monkeypatch.setenv("AEGIS_AUDIT_CHECKPOINT_LEGACY_KEY", OLD_SECRET)
    monkeypatch.setenv("AEGIS_AUDIT_CHECKPOINT_DIR", str(directory))


def rotate_to_new_key(monkeypatch, *, retain_old: bool):
    monkeypatch.setenv("AEGIS_AUDIT_CHECKPOINT_KEY", NEW_SECRET)
    monkeypatch.setenv("AEGIS_AUDIT_CHECKPOINT_KEY_ID", "key-v2")
    monkeypatch.setenv(
        "AEGIS_AUDIT_CHECKPOINT_PREVIOUS_KEYS",
        json.dumps({"key-v1": OLD_SECRET}) if retain_old else "{}",
    )


def test_key_usage_inventory_tracks_old_checkpoint_and_pending_intent(
    tmp_path,
    monkeypatch,
):
    directory = tmp_path / "checkpoints"
    configure_old_key(monkeypatch, directory)

    response_id = 71
    previous_hash = "a" * 64
    target_hash = "b" * 64

    write_audit_checkpoint(
        response_id=response_id,
        event_count=1,
        final_hash=previous_hash,
    )
    write_checkpoint_intent(
        response_id=response_id,
        event_count=2,
        final_hash=target_hash,
        previous_event_count=1,
        previous_final_hash=previous_hash,
    )

    rotate_to_new_key(monkeypatch, retain_old=True)
    report = inspect_checkpoint_key_usage(directory)

    assert report["active_key_id"] == "key-v2"
    assert report["referenced_key_ids"] == ["key-v1"]
    assert report["key_usage"]["key-v1"] == [
        {
            "file": str(directory / f"response_{response_id}.json"),
            "document_type": "checkpoint",
        },
        {
            "file": str(checkpoint_intent_path(directory, response_id)),
            "document_type": "pending_intent",
        },
    ]
    assert report["missing_key_ids"] == []
    assert report["invalid_or_unverifiable_documents"] == []
    assert report["retirement_assessment"] == "review_required"
    assert "key-v1" not in report[
        "configured_non_active_keys_without_references"
    ]


def test_pending_intent_survives_rotation_and_publishes_with_new_key(
    tmp_path,
    monkeypatch,
):
    directory = tmp_path / "checkpoints"
    configure_old_key(monkeypatch, directory)

    response_id = 72
    previous_hash = "c" * 64
    target_hash = "d" * 64

    write_audit_checkpoint(
        response_id=response_id,
        event_count=1,
        final_hash=previous_hash,
    )
    write_checkpoint_intent(
        response_id=response_id,
        event_count=2,
        final_hash=target_hash,
        previous_event_count=1,
        previous_final_hash=previous_hash,
    )

    rotate_to_new_key(monkeypatch, retain_old=True)

    intent = verify_checkpoint_intent(response_id)
    assert intent["valid"] is True
    assert intent["intent"]["key_id"] == "key-v1"

    published = publish_checkpoint_intent(
        response_id=response_id,
        event_count=2,
        final_hash=target_hash,
    )

    assert published["published"] is True
    assert checkpoint_intent_path(directory, response_id).exists() is False

    checkpoint = verify_audit_checkpoint(
        response_id=response_id,
        event_count=2,
        final_hash=target_hash,
    )
    assert checkpoint["valid"] is True
    assert checkpoint["checkpoint"]["key_id"] == "key-v2"

    report = inspect_checkpoint_key_usage(directory)
    assert report["referenced_key_ids"] == ["key-v2"]
    assert report["key_usage"]["key-v2"][0]["document_type"] == "checkpoint"


def test_key_usage_inventory_blocks_retirement_when_old_key_is_missing(
    tmp_path,
    monkeypatch,
):
    directory = tmp_path / "checkpoints"
    configure_old_key(monkeypatch, directory)

    response_id = 73
    write_checkpoint_intent(
        response_id=response_id,
        event_count=1,
        final_hash="e" * 64,
        previous_event_count=0,
        previous_final_hash="0" * 64,
    )

    rotate_to_new_key(monkeypatch, retain_old=False)
    report = inspect_checkpoint_key_usage(directory)

    assert report["missing_key_ids"] == ["key-v1"]
    assert report["retirement_assessment"] == "blocked"
    assert report["invalid_or_unverifiable_documents"][0]["key_id"] == "key-v1"
    assert report["invalid_or_unverifiable_documents"][0]["key_available"] is False
    assert report["invalid_or_unverifiable_documents"][0]["signature_valid"] is False
