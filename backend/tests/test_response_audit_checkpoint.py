
import json

from app.response.audit_checkpoint import (
    verify_audit_checkpoint,
    write_audit_checkpoint,
)
from concurrent.futures import ThreadPoolExecutor
import multiprocessing

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


def test_checkpoint_can_advance_from_valid_previous_checkpoint(
    monkeypatch,
    tmp_path,
):
    configure_checkpoint(monkeypatch, tmp_path)

    previous_hash = "a" * 64
    current_hash = "b" * 64

    write_audit_checkpoint(
        response_id=21,
        event_count=3,
        final_hash=previous_hash,
    )

    written = write_audit_checkpoint(
        response_id=21,
        event_count=4,
        final_hash=current_hash,
        previous_event_count=3,
        previous_final_hash=previous_hash,
    )

    result = verify_audit_checkpoint(
        response_id=21,
        event_count=4,
        final_hash=current_hash,
    )

    assert written["event_count"] == 4
    assert result["valid"] is True


def test_checkpoint_cannot_recover_when_previous_checkpoint_is_missing(
    monkeypatch,
    tmp_path,
):
    configure_checkpoint(monkeypatch, tmp_path)

    try:
        write_audit_checkpoint(
            response_id=22,
            event_count=4,
            final_hash="b" * 64,
            previous_event_count=3,
            previous_final_hash="a" * 64,
        )
    except RuntimeError as exc:
        assert "missing or invalid" in str(exc).lower()
    else:
        raise AssertionError(
            "Recovery accepted a missing previous checkpoint."
        )


def test_checkpoint_cannot_recover_from_tampered_previous_checkpoint(
    monkeypatch,
    tmp_path,
):
    configure_checkpoint(monkeypatch, tmp_path)

    previous_hash = "a" * 64

    write_audit_checkpoint(
        response_id=23,
        event_count=3,
        final_hash=previous_hash,
    )

    checkpoint_path = tmp_path / "response_23.json"
    document = json.loads(checkpoint_path.read_text())
    document["signature"] = "0" * 64
    checkpoint_path.write_text(json.dumps(document))

    try:
        write_audit_checkpoint(
            response_id=23,
            event_count=4,
            final_hash="b" * 64,
            previous_event_count=3,
            previous_final_hash=previous_hash,
        )
    except RuntimeError as exc:
        assert "missing or invalid" in str(exc).lower()
    else:
        raise AssertionError(
            "Recovery accepted a tampered previous checkpoint."
        )

    assert json.loads(checkpoint_path.read_text()) == document


def test_checkpoint_rejects_nonsequential_event_count(
    monkeypatch,
    tmp_path,
):
    configure_checkpoint(monkeypatch, tmp_path)

    previous_hash = "a" * 64

    write_audit_checkpoint(
        response_id=24,
        event_count=3,
        final_hash=previous_hash,
    )

    try:
        write_audit_checkpoint(
            response_id=24,
            event_count=5,
            final_hash="b" * 64,
            previous_event_count=3,
            previous_final_hash=previous_hash,
        )
    except ValueError as exc:
        assert "sequential" in str(exc).lower()
    else:
        raise AssertionError(
            "A nonsequential checkpoint update was accepted."
        )


def test_failed_checkpoint_replacement_preserves_previous_checkpoint(
    monkeypatch,
    tmp_path,
):
    from app.response import audit_checkpoint

    configure_checkpoint(monkeypatch, tmp_path)

    previous_hash = "a" * 64
    next_hash = "b" * 64

    write_audit_checkpoint(
        response_id=31,
        event_count=1,
        final_hash=previous_hash,
    )

    checkpoint_path = tmp_path / "response_31.json"
    original_document = json.loads(checkpoint_path.read_text())

    def fail_replace(source, destination):
        raise OSError("Simulated atomic replacement failure.")

    monkeypatch.setattr(
        audit_checkpoint.os,
        "replace",
        fail_replace,
    )

    try:
        write_audit_checkpoint(
            response_id=31,
            event_count=2,
            final_hash=next_hash,
            previous_event_count=1,
            previous_final_hash=previous_hash,
        )
    except OSError as exc:
        assert "replacement failure" in str(exc).lower()
    else:
        raise AssertionError(
            "Failed checkpoint replacement was not reported."
        )

    assert json.loads(checkpoint_path.read_text()) == original_document

    verification = verify_audit_checkpoint(
        response_id=31,
        event_count=1,
        final_hash=previous_hash,
    )

    assert verification["valid"] is True
    assert list(tmp_path.glob(".response_31_*.tmp")) == []


def test_failed_initial_checkpoint_write_leaves_no_partial_file(
    monkeypatch,
    tmp_path,
):
    from app.response import audit_checkpoint

    configure_checkpoint(monkeypatch, tmp_path)

    def fail_replace(source, destination):
        raise OSError("Simulated initial checkpoint write failure.")

    monkeypatch.setattr(
        audit_checkpoint.os,
        "replace",
        fail_replace,
    )

    try:
        write_audit_checkpoint(
            response_id=32,
            event_count=1,
            final_hash="c" * 64,
        )
    except OSError as exc:
        assert "write failure" in str(exc).lower()
    else:
        raise AssertionError(
            "Failed initial checkpoint write was not reported."
        )

    assert not (tmp_path / "response_32.json").exists()
    assert list(tmp_path.glob(".response_32_*.tmp")) == []


def test_concurrent_checkpoint_advancement_allows_only_one_writer(
    monkeypatch,
    tmp_path,
):
    configure_checkpoint(monkeypatch, tmp_path)

    previous_hash = "a" * 64

    write_audit_checkpoint(
        response_id=41,
        event_count=1,
        final_hash=previous_hash,
    )

    def advance_checkpoint(final_hash):
        try:
            write_audit_checkpoint(
                response_id=41,
                event_count=2,
                final_hash=final_hash,
                previous_event_count=1,
                previous_final_hash=previous_hash,
            )
            return "success"
        except RuntimeError:
            return "rejected"

    candidate_hashes = [
        "b" * 64,
        "c" * 64,
    ]

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(advance_checkpoint, candidate_hashes)
        )

    assert results.count("success") == 1
    assert results.count("rejected") == 1

    checkpoint = json.loads(
        (tmp_path / "response_41.json").read_text()
    )

    assert checkpoint["payload"]["event_count"] == 2
    assert checkpoint["payload"]["final_hash"] in candidate_hashes

    verification = verify_audit_checkpoint(
        response_id=41,
        event_count=2,
        final_hash=checkpoint["payload"]["final_hash"],
    )

    assert verification["valid"] is True


def test_separate_processes_cannot_overwrite_same_checkpoint(
    monkeypatch,
    tmp_path,
):
    configure_checkpoint(monkeypatch, tmp_path)

    previous_hash = "a" * 64

    write_audit_checkpoint(
        response_id=42,
        event_count=1,
        final_hash=previous_hash,
    )

    context = multiprocessing.get_context("fork")
    start_event = context.Event()
    results = context.Queue()

    def advance_checkpoint(final_hash):
        try:
            start_event.wait(timeout=10)

            write_audit_checkpoint(
                response_id=42,
                event_count=2,
                final_hash=final_hash,
                previous_event_count=1,
                previous_final_hash=previous_hash,
            )

            results.put("success")

        except RuntimeError:
            results.put("rejected")

        except Exception as exc:
            results.put(f"error: {type(exc).__name__}: {exc}")

    candidate_hashes = [
        "b" * 64,
        "c" * 64,
    ]

    processes = [
        context.Process(
            target=advance_checkpoint,
            args=(candidate_hash, ),
        )
        for candidate_hash in candidate_hashes
    ]

    try:
        for process in processes:
            process.start()

        start_event.set()

        outcomes = [
            results.get(timeout=15)
            for _ in processes
        ]

        for process in processes:
            process.join(timeout=15)

        assert all(not process.is_alive() for process in processes)
        assert all(process.exitcode == 0 for process in processes)

        assert outcomes.count("success") == 1
        assert outcomes.count("rejected") == 1

        checkpoint = json.loads(
            (tmp_path / "response_42.json").read_text()
        )

        assert checkpoint["payload"]["event_count"] == 2
        assert checkpoint["payload"]["final_hash"] in candidate_hashes

        verification = verify_audit_checkpoint(
            response_id=42,
            event_count=2,
            final_hash=checkpoint["payload"]["final_hash"],
        )

        assert verification["valid"] is True

    finally:
        start_event.set()

        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)

        results.close()
        results.join_thread()
