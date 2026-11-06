
from datetime import datetime, timedelta, timezone

import pytest

from app.detection.registry import get_detection_rules, get_detector
from app.evaluation.runner import create_isolated_database


RULES = {
    rule["rule_id"]: rule
    for rule in get_detection_rules()
}

INVALID_TIMESTAMP = "not-a-valid-timestamp"


def make_event(
    now,
    event_type="network_connection",
    source_ip="198.51.100.100",
    username=None,
    outcome=None,
    destination_ip="198.51.100.109",
    destination_port=443,
    occurred_at=None,
    received_at=None,
):
    return {
        "event_type": event_type,
        "source_ip": source_ip,
        "username": username,
        "outcome": outcome,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "protocol": "tcp",
        "occurred_at": (
            occurred_at or now
        ).isoformat() if isinstance(occurred_at or now, datetime)
        else occurred_at,
        "received_at": (
            received_at or now
        ).isoformat() if isinstance(received_at or now, datetime)
        else received_at,
    }


def insert_events(connection, events):
    for event in events:
        connection.execute(
            """
            INSERT INTO security_events (
                event_type,
                source_ip,
                username,
                outcome,
                description,
                occurred_at,
                received_at,
                destination_ip,
                destination_port,
                protocol
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["event_type"],
                event["source_ip"],
                event["username"],
                event["outcome"],
                "Malformed timestamp validation event",
                event["occurred_at"],
                event["received_at"],
                event["destination_ip"],
                event["destination_port"],
                event["protocol"],
            ),
        )

    connection.commit()


def evaluate(rule_id, events):
    connection = create_isolated_database()

    try:
        insert_events(connection, events)

        detector = get_detector(rule_id)

        return detector(
            connection,
            events[-1],
            RULES[rule_id],
        )

    finally:
        connection.close()


def test_brute_force_does_not_count_malformed_received_at():
    now = datetime.now(timezone.utc)

    events = [
        make_event(
            now,
            event_type="authentication",
            username="administrator",
            outcome="failure",
        )
        for _ in range(4)
    ]

    events.append(
        make_event(
            now,
            event_type="authentication",
            username="administrator",
            outcome="failure",
            received_at=INVALID_TIMESTAMP,
        )
    )

    assert evaluate("AEGIS-AUTH-001", events) is None


def test_password_spraying_does_not_count_malformed_occurred_at():
    now = datetime.now(timezone.utc)

    events = [
        make_event(
            now,
            event_type="authentication",
            username=f"user_{index}",
            outcome="failure",
        )
        for index in range(4)
    ]

    events.append(
        make_event(
            now,
            event_type="authentication",
            username="malformed_time_user",
            outcome="failure",
            occurred_at=INVALID_TIMESTAMP,
        )
    )

    assert evaluate("AEGIS-AUTH-002", events) is None


def test_port_scan_does_not_count_malformed_received_at():
    now = datetime.now(timezone.utc)

    events = [
        make_event(
            now,
            destination_port=20000 + index,
        )
        for index in range(9)
    ]

    events.append(
        make_event(
            now,
            destination_port=20009,
            received_at=INVALID_TIMESTAMP,
        )
    )

    assert evaluate("AEGIS-NET-001", events) is None


def test_horizontal_scan_does_not_count_malformed_received_at():
    now = datetime.now(timezone.utc)

    events = [
        make_event(
            now,
            destination_ip=f"198.51.100.{index + 1}",
        )
        for index in range(9)
    ]

    events.append(
        make_event(
            now,
            destination_ip="198.51.100.10",
            received_at=INVALID_TIMESTAMP,
        )
    )

    assert evaluate("AEGIS-NET-002", events) is None


def test_service_sweep_does_not_count_malformed_received_at():
    now = datetime.now(timezone.utc)

    events = []

    for host in range(1, 5):
        for port in range(4):
            events.append(
                make_event(
                    now,
                    destination_ip=f"198.51.100.{host}",
                    destination_port=8000 + port,
                )
            )

    for port in range(3):
        events.append(
            make_event(
                now,
                destination_ip="198.51.100.5",
                destination_port=8000 + port,
            )
        )

    events.append(
        make_event(
            now,
            destination_ip="198.51.100.5",
            destination_port=8003,
            received_at=INVALID_TIMESTAMP,
        )
    )

    assert len(events) == 20
    assert evaluate("AEGIS-NET-003", events) is None


def test_beaconing_skips_malformed_occurred_at():
    now = datetime.now(timezone.utc)

    events = [
        make_event(
            now,
            occurred_at=now - timedelta(seconds=60 * index),
        )
        for index in range(6)
    ]

    events[-1]["occurred_at"] = INVALID_TIMESTAMP

    assert evaluate("AEGIS-NET-004", events) is None
