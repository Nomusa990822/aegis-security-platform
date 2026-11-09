
import fcntl
import hashlib
import hmac
import json
import os
import re
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

CHECKPOINT_SCHEMA_VERSION = 2
LEGACY_CHECKPOINT_SCHEMA_VERSION = 1
GENESIS_HASH = "0" * 64

KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def _validate_key_id(key_id: str) -> None:
    if not isinstance(key_id, str) or not KEY_ID_PATTERN.fullmatch(key_id):
        raise ValueError(
            "Checkpoint key ID must contain 1-64 letters, digits, "
            "periods, underscores, or hyphens."
        )


def load_checkpoint_configuration():
    active_secret = os.getenv("AEGIS_AUDIT_CHECKPOINT_KEY", "")
    active_key_id = os.getenv(
        "AEGIS_AUDIT_CHECKPOINT_KEY_ID",
        "default",
    )
    previous_keys_raw = os.getenv(
        "AEGIS_AUDIT_CHECKPOINT_PREVIOUS_KEYS",
        "{}",
    )
    legacy_secret = os.getenv(
        "AEGIS_AUDIT_CHECKPOINT_LEGACY_KEY",
        active_secret,
    )
    directory = os.getenv("AEGIS_AUDIT_CHECKPOINT_DIR", "")

    if len(active_secret) < 32:
        raise ValueError(
            "AEGIS_AUDIT_CHECKPOINT_KEY must contain at least 32 characters."
        )

    if len(legacy_secret) < 32:
        raise ValueError(
            "AEGIS_AUDIT_CHECKPOINT_LEGACY_KEY must contain at least "
            "32 characters."
        )

    _validate_key_id(active_key_id)

    if not directory:
        raise ValueError(
            "AEGIS_AUDIT_CHECKPOINT_DIR must be configured."
        )

    
    try:
        previous_keys = json.loads(
            previous_keys_raw,
            object_pairs_hook=reject_duplicate_json_keys,
        )
    except json.JSONDecodeError as exc:
        raise ValueError(
            "AEGIS_AUDIT_CHECKPOINT_PREVIOUS_KEYS must contain valid JSON."
        ) from exc


    if not isinstance(previous_keys, dict):
        raise ValueError(
            "AEGIS_AUDIT_CHECKPOINT_PREVIOUS_KEYS must be a JSON object."
        )

    keyring = {}

    for key_id, secret in previous_keys.items():
        _validate_key_id(key_id)

        if key_id == active_key_id:
            raise ValueError(
                "The active checkpoint key ID cannot also be a previous key."
            )

        if not isinstance(secret, str) or len(secret) < 32:
            raise ValueError(
                f"Previous checkpoint key {key_id!r} must contain "
                "at least 32 characters."
            )

        keyring[key_id] = secret.encode("utf-8")

    keyring[active_key_id] = active_secret.encode("utf-8")

    return (
        active_secret.encode("utf-8"),
        active_key_id,
        keyring,
        legacy_secret.encode("utf-8"),
        Path(directory),
    )



def reject_duplicate_json_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    """Reject duplicate keys instead of silently overwriting them."""
    result = {}

    for key, value in pairs:
        if key in result:
            raise ValueError(
                f"Duplicate JSON key in checkpoint configuration: {key}"
            )

        result[key] = value

    return result


def checkpoint_path(directory: Path, response_id: int) -> Path:
    if (
        not isinstance(response_id, int)
        or isinstance(response_id, bool)
        or response_id < 1
    ):
        raise ValueError("response_id must be a positive integer.")

    return directory / f"response_{response_id}.json"


@contextmanager
def checkpoint_lock(
    directory: Path,
    response_id: int,
) -> Iterator[None]:
    """Serialize checkpoint writes across threads and Linux processes."""
    lock_path = directory / f"response_{response_id}.lock"

    lock_fd = os.open(
        lock_path,
        os.O_CREAT | os.O_RDWR,
        0o600,
    )

    try:
        with os.fdopen(lock_fd, "r") as lock_file:
            lock_fd = -1

            fcntl.flock(
                lock_file.fileno(),
                fcntl.LOCK_EX,
            )

            try:
                yield
            finally:
                fcntl.flock(
                    lock_file.fileno(),
                    fcntl.LOCK_UN,
                )
    finally:
        if lock_fd >= 0:
            os.close(lock_fd)


def canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sign_checkpoint(payload: dict[str, Any], secret: bytes) -> str:
    return hmac.new(
        secret,
        canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()


def verify_audit_checkpoint(
    response_id: int,
    event_count: int,
    final_hash: str,
) -> dict[str, Any]:
    """Verify a signed checkpoint using its identified signing key."""
    try:
        (
            active_secret,
            active_key_id,
            keyring,
            legacy_secret,
            directory,
        ) = load_checkpoint_configuration()

        path = checkpoint_path(directory, response_id)

        with path.open("r", encoding="utf-8") as checkpoint_file:
            document = json.load(
                checkpoint_file,
                object_pairs_hook=reject_duplicate_json_keys,
            )

        if not isinstance(document, dict):
            raise ValueError("Checkpoint document must be a JSON object.")

        payload = document.get("payload")
        signature = document.get("signature")

        if not isinstance(payload, dict):
            raise ValueError("Checkpoint payload is missing or invalid.")

        if not isinstance(signature, str):
            raise ValueError("Checkpoint signature is missing or invalid.")

        schema_version = payload.get("schema_version")

        if schema_version == LEGACY_CHECKPOINT_SCHEMA_VERSION:
            signing_secret = legacy_secret

        elif schema_version == CHECKPOINT_SCHEMA_VERSION:
            key_id = payload.get("key_id")

            if not isinstance(key_id, str):
                raise ValueError(
                    "Version 2 checkpoint is missing its key ID."
                )

            signing_secret = keyring.get(key_id)

            if signing_secret is None:
                raise ValueError(
                    f"Checkpoint signing key {key_id!r} is not available."
                )

        else:
            raise ValueError("Unsupported checkpoint schema version.")

        received_signature = sign_checkpoint(
            payload,
            signing_secret,
        )

        if not hmac.compare_digest(signature, received_signature):
            raise ValueError("Checkpoint signature is invalid.")

        if payload.get("response_id") != response_id:
            raise ValueError("Checkpoint response ID does not match.")

        if payload.get("event_count") != event_count:
            raise ValueError("Checkpoint event count does not match.")

        if payload.get("final_hash") != final_hash:
            raise ValueError("Checkpoint final hash does not match.")

        return {
            "valid": True,
            "errors": [],
            "checkpoint": payload,
        }

    except FileNotFoundError:
        return {
            "valid": False,
            "errors": ["Audit checkpoint file is missing."],
            "checkpoint": None,
        }

    except (ValueError, json.JSONDecodeError, TypeError, OSError) as exc:
        return {
            "valid": False,
            "errors": [str(exc)],
            "checkpoint": None,
        }


def write_audit_checkpoint(
    response_id: int,
    event_count: int,
    final_hash: str,
    previous_event_count: int | None = None,
    previous_final_hash: str | None = None,
) -> dict[str, Any]:
    """Write a versioned signed checkpoint with serialized advancement."""
    if (
        not isinstance(event_count, int)
        or isinstance(event_count, bool)
        or event_count <= 0
    ):
        raise ValueError("event_count must be a positive integer.")

    if (
        not isinstance(final_hash, str)
        or len(final_hash) != 64
        or any(char not in "0123456789abcdef" for char in final_hash)
    ):
        raise ValueError("final_hash must be a lowercase SHA-256 hex digest.")

    if (previous_event_count is None) != (previous_final_hash is None):
        raise ValueError(
            "Previous checkpoint count and hash must be supplied together."
        )

    if previous_event_count is not None:
        if (
            not isinstance(previous_event_count, int)
            or isinstance(previous_event_count, bool)
            or previous_event_count < 0
        ):
            raise ValueError(
                "previous_event_count must be a non-negative integer."
            )

        if event_count != previous_event_count + 1:
            raise ValueError(
                "event_count must be sequential with the previous checkpoint."
            )

        if (
            not isinstance(previous_final_hash, str)
            or len(previous_final_hash) != 64
            or any(char not in "0123456789abcdef" for char in previous_final_hash)
        ):
            raise ValueError(
                "previous_final_hash must be a lowercase SHA-256 hex digest."
            )

        if previous_event_count == 0 and previous_final_hash != GENESIS_HASH:
            raise ValueError(
                "The initial checkpoint must use the genesis hash."
            )

    (
        active_secret,
        active_key_id,
        keyring,
        legacy_secret,
        directory,
    ) = load_checkpoint_configuration()

    directory.mkdir(parents=True, exist_ok=True)

    destination = checkpoint_path(directory, response_id)

    with checkpoint_lock(directory, response_id):
        if previous_event_count is None:
            if destination.exists():
                raise RuntimeError(
                    "Unexpected existing checkpoint for a new audit chain."
                )

        elif previous_event_count == 0:
            if destination.exists():
                raise RuntimeError(
                    "Unexpected existing checkpoint for a new audit chain."
                )

        else:
            previous_verification = verify_audit_checkpoint(
                response_id=response_id,
                event_count=previous_event_count,
                final_hash=previous_final_hash,
            )

            if not previous_verification["valid"]:
                raise RuntimeError(
                    "Existing audit checkpoint is missing or invalid, "
                    "refusing to replace it."
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
            "signature": sign_checkpoint(
                payload,
                active_secret,
            ),
        }

        temporary_path = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=directory,
                prefix=f"response_{response_id}_",
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
            os.replace(temporary_path, destination)
            os.chmod(destination, 0o600)

        finally:
            if temporary_path is not None and temporary_path.exists():
                temporary_path.unlink()

    return payload
