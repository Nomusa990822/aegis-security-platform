
import json

from app.response.audit_checkpoint import (
    verify_audit_checkpoint,
    write_audit_checkpoint,
)


TEST_SECRET = "test-audit-checkpoint-secret-" + ("x" * 32)
TEST_HASH = "a" * 64


def configure_checkpoint(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "AEGIS_AUDIT_CHECKPOINT_KEY",
        TEST_SECRET,
    )
    monkeypatch.setenv(
        "AEGIS_AUDIT_CHECKPOINT_DIR",
        str(tmp_path),
    )


def test_checkpoint_write_and_verify(monkeypatch, tmp_path):
    configure_checkpoint(monkeypatch, tmp_path)

    written = write_audit_checkpoint(
        response_id=12,
        event_count=3,
        final_hash=TEST_HASH,
    )

    result = verify_audit_checkpoint(
        response_id=12,
        event_count=3,
        final_hash=TEST_HASH,
    )

    assert written["response_id"] == 12
    assert written["event_count"] == 3
    assert written["final_hash"] == TEST_HASH
    assert result["valid"] is True
    assert result["errors"] == []


def test_checkpoint_detects_modified_payload(monkeypatch, tmp_path):
    configure_checkpoint(monkeypatch, tmp_path)

    write_audit_checkpoint(12, 3, TEST_HASH)

    checkpoint_path = tmp_path / "response_12.json"
    document = json.loads(checkpoint_path.read_text())

    document["payload"]["event_count"] = 99
    checkpoint_path.write_text(json.dumps(document))

    result = verify_audit_checkpoint(12, 99, TEST_HASH)

    assert result["valid"] is False
    assert any(
        "signature is invalid" in error.lower()
        for error in result["errors"]
    )


def test_checkpoint_detects_wrong_database_event_count(
    monkeypatch,
    tmp_path,
):
    configure_checkpoint(monkeypatch, tmp_path)

    write_audit_checkpoint(12, 3, TEST_HASH)

    result = verify_audit_checkpoint(12, 4, TEST_HASH)

    assert result["valid"] is False
    assert any(
        "event count does not match" in error.lower()
        for error in result["errors"]
    )


def test_checkpoint_detects_wrong_database_final_hash(
    monkeypatch,
    tmp_path,
):
    configure_checkpoint(monkeypatch, tmp_path)

    write_audit_checkpoint(12, 3, TEST_HASH)

    result = verify_audit_checkpoint(12, 3, "b" * 64)

    assert result["valid"] is False
    assert any(
        "final hash does not match" in error.lower()
        for error in result["errors"]
    )


def test_checkpoint_detects_missing_file(monkeypatch, tmp_path):
    configure_checkpoint(monkeypatch, tmp_path)

    result = verify_audit_checkpoint(12, 3, TEST_HASH)

    assert result["valid"] is False
    assert any(
        "file is missing" in error.lower()
        for error in result["errors"]
    )


def test_checkpoint_requires_strong_secret(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_AUDIT_CHECKPOINT_KEY", "short")
    monkeypatch.setenv(
        "AEGIS_AUDIT_CHECKPOINT_DIR",
        str(tmp_path),
    )

    result = verify_audit_checkpoint(12, 3, TEST_HASH)

    assert result["valid"] is False
    assert any(
        "at least 32 characters" in error.lower()
        for error in result["errors"]
    )


def test_checkpoint_requires_configured_directory(monkeypatch):
    monkeypatch.setenv(
        "AEGIS_AUDIT_CHECKPOINT_KEY",
        TEST_SECRET,
    )
    monkeypatch.delenv(
        "AEGIS_AUDIT_CHECKPOINT_DIR",
        raising=False,
    )

    result = verify_audit_checkpoint(12, 3, TEST_HASH)

    assert result["valid"] is False
    assert any(
        "must be configured" in error.lower()
        for error in result["errors"]
    )


def test_checkpoint_rejects_invalid_response_id(monkeypatch, tmp_path):
    configure_checkpoint(monkeypatch, tmp_path)

    try:
        write_audit_checkpoint(0, 3, TEST_HASH)
    except ValueError as exc:
        assert "response_id" in str(exc)
    else:
        raise AssertionError("Invalid response ID was accepted.")


def test_checkpoint_rejects_invalid_hash(monkeypatch, tmp_path):
    configure_checkpoint(monkeypatch, tmp_path)

    try:
        write_audit_checkpoint(12, 3, "not-a-hash")
    except ValueError as exc:
        assert "final_hash" in str(exc)
    else:
        raise AssertionError("Invalid final hash was accepted.")
