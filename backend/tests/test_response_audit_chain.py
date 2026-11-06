
import copy

import pytest

from app.response.audit_chain import (
    GENESIS_HASH,
    calculate_event_hash,
    verify_hash_chain,
)


def make_events():
    events = [
        {
            "id": 10,
            "response_id": 1,
            "alert_id": 20,
            "event": "response_request_created",
            "actor": "analyst-alpha",
            "details": {
                "action": "block_ip",
                "target": "8.8.8.8",
            },
            "created_at": "2026-11-06T10:00:00+00:00",
        },
        {
            "id": 11,
            "response_id": 1,
            "alert_id": 20,
            "event": "response_approved",
            "actor": "approver-beta",
            "details": {
                "new_status": "approved",
                "executed": False,
            },
            "created_at": "2026-11-06T10:01:00+00:00",
        },
    ]

    previous_hash = GENESIS_HASH

    for event in events:
        event["previous_hash"] = previous_hash
        event["event_hash"] = calculate_event_hash(
            event,
            previous_hash,
        )
        previous_hash = event["event_hash"]

    return events


def test_valid_hash_chain_passes():
    result = verify_hash_chain(make_events())

    assert result["valid"] is True
    assert result["errors"] == []
    assert result["event_count"] == 2


def test_hash_calculation_is_deterministic():
    event = make_events()[0]

    first = calculate_event_hash(
        event,
        GENESIS_HASH,
    )
    second = calculate_event_hash(
        event,
        GENESIS_HASH,
    )

    assert first == second


def test_hash_changes_when_event_details_change():
    event = make_events()[0]
    original = calculate_event_hash(event, GENESIS_HASH)

    modified = copy.deepcopy(event)
    modified["details"]["target"] = "1.1.1.1"

    changed = calculate_event_hash(modified, GENESIS_HASH)

    assert original != changed


def test_modified_event_is_detected():
    events = make_events()
    events[0]["actor"] = "unauthorised-user"

    result = verify_hash_chain(events)

    assert result["valid"] is False


def test_modified_hash_is_detected():
    events = make_events()
    events[0]["event_hash"] = "f" * 64

    result = verify_hash_chain(events)

    assert result["valid"] is False


def test_modified_previous_hash_is_detected():
    events = make_events()
    events[1]["previous_hash"] = "f" * 64

    result = verify_hash_chain(events)

    assert result["valid"] is False


def test_reordered_events_are_detected():
    events = make_events()
    events.reverse()

    result = verify_hash_chain(events)

    assert result["valid"] is False


def test_deleted_middle_event_is_detected():
    events = make_events()
    events.pop(0)

    result = verify_hash_chain(events)

    assert result["valid"] is False


def test_mixed_response_ids_are_detected():
    events = make_events()
    events[1]["response_id"] = 999

    result = verify_hash_chain(events)

    assert result["valid"] is False


def test_non_increasing_event_ids_are_detected():
    events = make_events()
    events[1]["id"] = events[0]["id"]

    result = verify_hash_chain(events)

    assert result["valid"] is False


def test_empty_chain_is_rejected():
    result = verify_hash_chain([])

    assert result["valid"] is False
    assert result["event_count"] == 0


def test_non_list_input_is_rejected():
    result = verify_hash_chain(None)

    assert result["valid"] is False


def test_verification_does_not_modify_events():
    events = make_events()
    original = copy.deepcopy(events)

    verify_hash_chain(events)

    assert events == original
