import hashlib
import json
import os
from pathlib import Path

from app.response.audit_checkpoint import (
    LEGACY_CHECKPOINT_SCHEMA_VERSION,
    sign_checkpoint,
    write_audit_checkpoint,
)
from app.response.checkpoint_intent import (
    checkpoint_intent_path,
    write_checkpoint_intent,
)
from app.response.checkpoint_key_rotation import (
    validate_proposed_checkpoint_configuration,
)


OLD_SECRET = "aegis-preflight-old-secret-" + ("o" * 32)
NEW_SECRET = "aegis-preflight-new-secret-" + ("n" * 32)
THIRD_SECRET = "aegis-preflight-third-secret-" + ("t" * 32)


def configure_current_key(monkeypatch, directory: Path):
    monkeypatch.setenv("AEGIS_AUDIT_CHECKPOINT_KEY", OLD_SECRET)
    monkeypatch.setenv("AEGIS_AUDIT_CHECKPOINT_KEY_ID", "key-v1")
    monkeypatch.setenv("AEGIS_AUDIT_CHECKPOINT_PREVIOUS_KEYS", "{}")
    monkeypatch.setenv("AEGIS_AUDIT_CHECKPOINT_LEGACY_KEY", OLD_SECRET)
    monkeypatch.setenv("AEGIS_AUDIT_CHECKPOINT_DIR", str(directory))


def proposed_configuration(
    directory: Path,
    *,
    previous_keys=None,
    legacy_secret=OLD_SECRET,
):
    return validate_proposed_checkpoint_configuration(
        directory,
        active_secret=NEW_SECRET,
        active_key_id="key-v2",
        previous_keys=previous_keys or {},
        legacy_secret=legacy_secret,
    )


def test_preflight_accepts_rotation_that_retains_all_required_keys(
    tmp_path,
    monkeypatch,
):
    directory = tmp_path / "checkpoints"
    configure_current_key(monkeypatch, directory)

    write_audit_checkpoint(
        response_id=81,
        event_count=1,
        final_hash="a" * 64,
    )
    write_checkpoint_intent(
        response_id=82,
        event_count=1,
        final_hash="b" * 64,
        previous_event_count=0,
        previous_final_hash="0" * 64,
    )

    report = proposed_configuration(
        directory,
        previous_keys={"key-v1": OLD_SECRET},
    )

    assert report["valid"] is True
    assert report["documents_inspected"] == 2
    assert report["documents_verified"] == 2
    assert report["verification_failures"] == []
    assert report["filesystem_errors"] == []


def test_preflight_rejects_rotation_that_drops_a_required_previous_key(
    tmp_path,
    monkeypatch,
):
    directory = tmp_path / "checkpoints"
    configure_current_key(monkeypatch, directory)

    write_checkpoint_intent(
        response_id=83,
        event_count=1,
        final_hash="c" * 64,
        previous_event_count=0,
        previous_final_hash="0" * 64,
    )

    report = proposed_configuration(directory)

    assert report["valid"] is False
    assert len(report["verification_failures"]) == 1
    assert report["verification_failures"][0]["key_id"] == "key-v1"
    assert report["verification_failures"][0]["key_available"] is False


def test_preflight_rejects_wrong_legacy_key(tmp_path, monkeypatch):
    directory = tmp_path / "checkpoints"
    configure_current_key(monkeypatch, directory)
    response_id = 84

    payload = {
        "schema_version": LEGACY_CHECKPOINT_SCHEMA_VERSION,
        "response_id": response_id,
        "event_count": 1,
        "final_hash": "d" * 64,
    }
    document = {
        "payload": payload,
        "signature": sign_checkpoint(payload, OLD_SECRET.encode("utf-8")),
    }
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"response_{response_id}.json").write_text(
        json.dumps(document),
        encoding="utf-8",
    )

    report = proposed_configuration(
        directory,
        legacy_secret=THIRD_SECRET,
    )

    assert report["valid"] is False
    assert report["verification_failures"][0]["key_id"] == "__legacy__"
    assert report["verification_failures"][0]["key_available"] is True
    assert report["verification_failures"][0]["signature_valid"] is False


def test_preflight_rejects_tampered_checkpoint_signature(
    tmp_path,
    monkeypatch,
):
    directory = tmp_path / "checkpoints"
    configure_current_key(monkeypatch, directory)

    write_audit_checkpoint(
        response_id=85,
        event_count=1,
        final_hash="e" * 64,
    )
    checkpoint_path = directory / "response_85.json"
    document = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    document["signature"] = "0" * 64
    checkpoint_path.write_text(
        json.dumps(document),
        encoding="utf-8",
    )

    report = proposed_configuration(
        directory,
        previous_keys={"key-v1": OLD_SECRET},
    )

    assert report["valid"] is False
    assert report["verification_failures"][0]["signature_valid"] is False


def test_preflight_checks_quarantined_intent_evidence(
    tmp_path,
    monkeypatch,
):
    directory = tmp_path / "checkpoints"
    configure_current_key(monkeypatch, directory)
    response_id = 86

    write_checkpoint_intent(
        response_id=response_id,
        event_count=1,
        final_hash="f" * 64,
        previous_event_count=0,
        previous_final_hash="0" * 64,
    )

    quarantine_directory = directory / "quarantine"
    quarantine_directory.mkdir(mode=0o700)
    original_path = checkpoint_intent_path(directory, response_id)
    digest = hashlib.sha256(original_path.read_bytes()).hexdigest()
    evidence_path = quarantine_directory / (
        f"response_{response_id}_{digest}.pending.json"
    )
    os.replace(original_path, evidence_path)

    report = proposed_configuration(directory)

    assert report["valid"] is False
    assert report["documents_inspected"] == 1
    assert report["verification_failures"][0]["document_type"] == "quarantined_intent"
    assert report["verification_failures"][0]["key_id"] == "key-v1"
