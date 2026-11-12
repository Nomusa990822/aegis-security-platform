"""Privacy-conscious writer for IAM security events."""

import json
import re
import sqlite3
import uuid
from collections.abc import Mapping
from typing import Any

_EVENT_TYPE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_FORBIDDEN_KEYS = ("password", "token", "secret", "credential", "recovery", "code")


def _validate_metadata(value: Any, *, depth: int = 0) -> None:
    if depth > 4:
        raise ValueError("security event metadata is too deeply nested")
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError("security event metadata keys must be strings")
            if any(part in key.casefold() for part in _FORBIDDEN_KEYS):
                raise ValueError("sensitive values must not be written to security events")
            _validate_metadata(child, depth=depth + 1)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _validate_metadata(child, depth=depth + 1)
    elif value is not None and not isinstance(value, (str, int, float, bool)):
        raise ValueError("security event metadata must contain JSON scalar values")


def record_security_event(
    connection: sqlite3.Connection, *, event_type: str, occurred_at: str,
    success: bool, user_id: str | None = None, source_ip: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> str:
    """Persist an IAM event without accepting credentials or bearer material."""
    if not isinstance(event_type, str) or not _EVENT_TYPE.fullmatch(event_type):
        raise ValueError("invalid IAM security event type")
    if not isinstance(occurred_at, str) or not occurred_at:
        raise ValueError("occurred_at is required")
    if not isinstance(success, bool):
        raise ValueError("success must be a boolean")
    safe_metadata = {} if metadata is None else metadata
    if not isinstance(safe_metadata, Mapping):
        raise ValueError("metadata must be a mapping")
    _validate_metadata(safe_metadata)
    metadata_json = json.dumps(
        safe_metadata, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    if len(metadata_json.encode("utf-8")) > 4096:
        raise ValueError("security event metadata exceeds 4096 bytes")
    event_id = str(uuid.uuid4())
    connection.execute(
        """INSERT INTO iam_security_events
           (id, user_id, event_type, occurred_at, source_ip, success, metadata_json)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (event_id, user_id, event_type, occurred_at, source_ip, int(success), metadata_json),
    )
    return event_id
