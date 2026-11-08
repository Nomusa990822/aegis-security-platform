import hmac
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from app.response.audit_checkpoint import (
    CHECKPOINT_SCHEMA_VERSION,
    checkpoint_lock,
    checkpoint_path,
    load_checkpoint_configuration,
    sign_checkpoint,
    verify_audit_checkpoint,
)


INTENT_SCHEMA_VERSION = 1


def checkpoint_intent_path(directory: Path, response_id: int) -> Path:
    if (
        not isinstance(response_id, int)
        or isinstance(response_id, bool)
        or response_id < 1
    ):
        raise ValueError("response_id must be a positive integer.")

    return directory / f"response_{response_id}.pending.json"


def _atomic_write_document(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f"{path.stem}_",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            json.dump(
                document,
                temporary_file,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            temporary_file.flush()
            os.fsync(temporary_file.fileno())

        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
        os.chmod(path, 0o600)

        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def _remove_intent(path: Path) -> None:
    path.unlink(missing_ok=True)
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def write_checkpoint_intent(
    response_id: int,
    event_count: int,
    final_hash: str,
    previous_event_count: int,
    previous_final_hash: str,
) -> dict[str, Any]:
    """Persist a signed description of the exact event about to be committed."""
    if (
        not isinstance(event_count, int)
        or isinstance(event_count, bool)
        or event_count < 1
    ):
        raise ValueError("event_count must be a positive integer.")

    if (
        not isinstance(previous_event_count, int)
        or isinstance(previous_event_count, bool)
        or previous_event_count < 0
        or event_count != previous_event_count + 1
    ):
        raise ValueError("Checkpoint intent event count must advance by one.")

    for field_name, value in (
        ("final_hash", final_hash),
        ("previous_final_hash", previous_final_hash),
    ):
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)
        ):
            raise ValueError(
                f"{field_name} must be a lowercase SHA-256 hex digest."
            )

    (
        active_secret,
        active_key_id,
        _keyring,
        _legacy_secret,
        directory,
    ) = load_checkpoint_configuration()

    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    intent_path = checkpoint_intent_path(directory, response_id)
    destination = checkpoint_path(directory, response_id)

    with checkpoint_lock(directory, response_id):
        if intent_path.exists():
            raise RuntimeError(
                "A pending checkpoint intent already exists; "
                "recovery or investigation is required."
            )

        if previous_event_count == 0:
            if previous_final_hash != "0" * 64:
                raise ValueError("Initial checkpoint intent must use the genesis hash.")
            if destination.exists():
                raise RuntimeError(
                    "Unexpected checkpoint exists for an initial audit event."
                )
        else:
            previous = verify_audit_checkpoint(
                response_id=response_id,
                event_count=previous_event_count,
                final_hash=previous_final_hash,
            )
            if not previous["valid"]:
                raise RuntimeError(
                    "Previous signed checkpoint is missing or invalid; "
                    "refusing to create a new intent."
                )

        payload = {
            "intent_schema_version": INTENT_SCHEMA_VERSION,
            "key_id": active_key_id,
            "response_id": response_id,
            "event_count": event_count,
            "final_hash": final_hash,
            "previous_event_count": previous_event_count,
            "previous_final_hash": previous_final_hash,
        }
        document = {
            "payload": payload,
            "signature": sign_checkpoint(payload, active_secret),
        }
        _atomic_write_document(intent_path, document)

    return payload


def verify_checkpoint_intent(response_id: int) -> dict[str, Any]:
    """Verify a pending intent using its identified active or retained key."""
    try:
        (
            _active_secret,
            _active_key_id,
            keyring,
            _legacy_secret,
            directory,
        ) = load_checkpoint_configuration()

        path = checkpoint_intent_path(directory, response_id)
        with path.open("r", encoding="utf-8") as intent_file:
            document = json.load(intent_file)

        if not isinstance(document, dict):
            raise ValueError("Checkpoint intent must be a JSON object.")

        payload = document.get("payload")
        signature = document.get("signature")
        if not isinstance(payload, dict) or not isinstance(signature, str):
            raise ValueError("Checkpoint intent payload or signature is invalid.")

        key_id = payload.get("key_id")
        secret = keyring.get(key_id) if isinstance(key_id, str) else None
        if secret is None:
            raise ValueError("Checkpoint intent signing key is unavailable.")

        expected = sign_checkpoint(payload, secret)
        if not hmac.compare_digest(signature, expected):
            raise ValueError("Checkpoint intent signature is invalid.")

        if payload.get("intent_schema_version") != INTENT_SCHEMA_VERSION:
            raise ValueError("Unsupported checkpoint intent schema version.")
        if payload.get("response_id") != response_id:
            raise ValueError("Checkpoint intent response ID does not match.")

        event_count = payload.get("event_count")
        previous_event_count = payload.get("previous_event_count")
        if (
            not isinstance(event_count, int)
            or isinstance(event_count, bool)
            or not isinstance(previous_event_count, int)
            or isinstance(previous_event_count, bool)
            or event_count != previous_event_count + 1
        ):
            raise ValueError("Checkpoint intent event counts are invalid.")

        for field_name in ("final_hash", "previous_final_hash"):
            value = payload.get(field_name)
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(char not in "0123456789abcdef" for char in value)
            ):
                raise ValueError(f"Checkpoint intent {field_name} is invalid.")

        return {"valid": True, "errors": [], "intent": payload}

    except FileNotFoundError:
        return {
            "valid": False,
            "errors": ["Pending checkpoint intent is missing."],
            "intent": None,
        }
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return {"valid": False, "errors": [str(exc)], "intent": None}


def publish_checkpoint_intent(
    response_id: int,
    event_count: int,
    final_hash: str,
) -> dict[str, Any]:
    """Publish only the exact database head authorised by a signed intent."""
    (
        active_secret,
        active_key_id,
        _keyring,
        _legacy_secret,
        directory,
    ) = load_checkpoint_configuration()

    intent_path = checkpoint_intent_path(directory, response_id)
    destination = checkpoint_path(directory, response_id)

    with checkpoint_lock(directory, response_id):
        verification = verify_checkpoint_intent(response_id)
        if not verification["valid"]:
            raise RuntimeError(
                "Pending checkpoint intent is invalid: "
                + "; ".join(verification["errors"])
            )

        intent = verification["intent"]
        if (
            intent["event_count"] != event_count
            or intent["final_hash"] != final_hash
        ):
            raise RuntimeError(
                "Database audit head does not match the signed checkpoint intent."
            )

        previous_count = intent["previous_event_count"]
        previous_hash = intent["previous_final_hash"]

        if destination.exists():
            current = verify_audit_checkpoint(
                response_id=response_id,
                event_count=event_count,
                final_hash=final_hash,
            )
            if current["valid"]:
                _remove_intent(intent_path)
                return {
                    "published": True,
                    "already_published": True,
                    "payload": current["checkpoint"],
                }

            if previous_count == 0:
                raise RuntimeError(
                    "Unexpected checkpoint exists before initial intent publication."
                )

            previous = verify_audit_checkpoint(
                response_id=response_id,
                event_count=previous_count,
                final_hash=previous_hash,
            )
            if not previous["valid"]:
                raise RuntimeError(
                    "Existing checkpoint is neither the signed intent target "
                    "nor its verified predecessor."
                )
        elif previous_count > 0:
            previous = verify_audit_checkpoint(
                response_id=response_id,
                event_count=previous_count,
                final_hash=previous_hash,
            )
            if not previous["valid"]:
                raise RuntimeError(
                    "Previous signed checkpoint is missing or invalid."
                )

        payload = {
            "schema_version": CHECKPOINT_SCHEMA_VERSION,
            "key_id": active_key_id,
            "response_id": response_id,
            "event_count": event_count,
            "final_hash": final_hash,
        }
        document = {
            "payload": payload,
            "signature": sign_checkpoint(payload, active_secret),
        }
        _atomic_write_document(destination, document)
        _remove_intent(intent_path)

    return {
        "published": True,
        "already_published": False,
        "payload": payload,
    }
