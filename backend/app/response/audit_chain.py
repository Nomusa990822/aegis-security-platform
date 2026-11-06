
import hashlib
import hmac
import json
from typing import Any


GENESIS_HASH = "0" * 64


def canonical_event_payload(
    event: dict[str, Any],
    previous_hash: str,
) -> dict[str, Any]:
    """Build the deterministic payload used to hash an audit event."""
    return {
        "id": event["id"],
        "response_id": event["response_id"],
        "alert_id": event["alert_id"],
        "event": event["event"],
        "actor": event["actor"],
        "details": event["details"],
        "created_at": event["created_at"],
        "previous_hash": previous_hash,
    }


def calculate_event_hash(
    event: dict[str, Any],
    previous_hash: str,
) -> str:
    """Calculate a SHA-256 hash for an audit event."""
    payload = canonical_event_payload(event, previous_hash)

    serialized = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def verify_hash_chain(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Verify ordering, linkage, and integrity of an audit event chain."""
    errors: list[str] = []

    if not isinstance(events, list):
        return {
            "valid": False,
            "errors": ["Audit events must be a list."],
            "event_count": 0,
            "final_hash": None,
        }

    if not events:
        return {
            "valid": False,
            "errors": ["Audit chain is empty."],
            "event_count": 0,
            "final_hash": None,
        }

    previous_hash = GENESIS_HASH
    previous_id = None
    response_id = None

    for index, event in enumerate(events):
        if not isinstance(event, dict):
            errors.append(f"Event at index {index} is not a dictionary.")
            continue

        required_fields = {
            "id",
            "response_id",
            "alert_id",
            "event",
            "actor",
            "details",
            "created_at",
            "previous_hash",
            "event_hash",
        }

        missing_fields = required_fields - event.keys()

        if missing_fields:
            errors.append(
                f"Event at index {index} is missing fields: "
                f"{', '.join(sorted(missing_fields))}."
            )
            continue

        event_id = event["id"]
        current_response_id = event["response_id"]

        if not isinstance(event_id, int) or isinstance(event_id, bool):
            errors.append(f"Event at index {index} has an invalid ID.")
            continue

        if not isinstance(current_response_id, int) or isinstance(
            current_response_id, bool
        ):
            errors.append(
                f"Event at index {index} has an invalid response ID."
            )
            continue

        if previous_id is not None and event_id <= previous_id:
            errors.append(
                f"Event ID {event_id} is not greater than "
                f"the previous event ID {previous_id}."
            )

        if response_id is None:
            response_id = current_response_id
        elif current_response_id != response_id:
            errors.append(
                f"Event ID {event_id} belongs to a different response."
            )

        stored_previous_hash = event["previous_hash"]

        if stored_previous_hash != previous_hash:
            errors.append(
                f"Event ID {event_id} has an invalid previous hash."
            )

        stored_hash = event["event_hash"]

        if (
            not isinstance(stored_hash, str)
            or len(stored_hash) != 64
            or any(char not in "0123456789abcdef" for char in stored_hash)
        ):
            errors.append(f"Event ID {event_id} has an invalid event hash.")
            previous_id = event_id
            continue

        try:
            expected_hash = calculate_event_hash(
                event,
                stored_previous_hash,
            )
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(
                f"Event ID {event_id} could not be hashed: {exc}."
            )
            previous_id = event_id
            continue

        if not hmac.compare_digest(stored_hash, expected_hash):
            errors.append(
                f"Event ID {event_id} hash does not match its contents."
            )

        previous_hash = stored_hash
        previous_id = event_id

    return {
        "valid": not errors,
        "errors": errors,
        "event_count": len(events),
        "final_hash": previous_hash,
    }
