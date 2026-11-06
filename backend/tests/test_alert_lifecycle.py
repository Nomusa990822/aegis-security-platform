from datetime import datetime, timedelta, timezone

import pytest

from app.detection.registry import get_detection_rules, get_detector
from app.evaluation.runner import create_isolated_database


RULES = {
    rule["rule_id"]: rule
    for rule in get_detection_rules()
}

ACTIVE_STATUSES = ("open", "investigating")
TERMINAL_STATUSES = ("resolved", "closed")

RULE_IDS = (
    "AEGIS-AUTH-001",
    "AEGIS-AUTH-002",
    "AEGIS-NET-001",
    "AEGIS-NET-002",
    "AEGIS-NET-003",
    "AEGIS-NET-004",
)


def make_event(
    now,
    event_type="network_connection",
    source_ip="198.51.100.100",
    username=None,
    outcome=None,
    destination_ip="198.51.100.109",
    destination_port=443,
    occurred_at=None,
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
        ).isoformat(),
        "received_at": now.isoformat(),
    }


def build_events(rule_id, now):
    if rule_id == "AEGIS-AUTH-001":
        return [
            make_event(
                now,
                event_type="authentication",
                username="administrator",
                outcome="failure",
            )
            for _ in range(5)
        ]

    if rule_id == "AEGIS-AUTH-002":
        return [
            make_event(
                now,
                event_type="authentication",
                username=f"user_{index}",
                outcome="failure",
            )
            for index in range(5)
        ]

    if rule_id == "AEGIS-NET-001":
        return [
            make_event(
                now,
                destination_port=20000 + index,
            )
            for index in range(10)
        ]

    if rule_id == "AEGIS-NET-002":
        return [
            make_event(
                now,
                destination_ip=f"198.51.100.{index + 1}",
                destination_port=443,
            )
            for index in range(10)
        ]

    if rule_id == "AEGIS-NET-003":
        events = []

        for host in range(1, 6):
            for port in range(4):
                events.append(
                    make_event(
                        now,
                        destination_ip=f"198.51.100.{host}",
                        destination_port=8000 + port,
                    )
                )

        return events

    if rule_id == "AEGIS-NET-004":
        return [
            make_event(
                now,
                occurred_at=now - timedelta(
                    seconds=60 * (5 - index)
                ),
            )
            for index in range(6)
        ]

    raise ValueError(f"Unsupported rule: {rule_id}")


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
                "Alert lifecycle validation event",
                event["occurred_at"],
                event["received_at"],
                event["destination_ip"],
                event["destination_port"],
                event["protocol"],
            ),
        )

    connection.commit()


@pytest.mark.parametrize("rule_id", RULE_IDS)
@pytest.mark.parametrize("status", ACTIVE_STATUSES)
def test_active_alert_is_reused(rule_id, status):
    """
    An existing open or investigating alert should be reused.
    A duplicate active incident should not be created.
    """
    connection = create_isolated_database()

    try:
        now = datetime.now(timezone.utc)
        events = build_events(rule_id, now)
        insert_events(connection, events)

        detector = get_detector(rule_id)
        rule = RULES[rule_id]
        event = events[-1]

        first_result = detector(connection, event, rule)

        assert first_result is not None
        assert first_result["created"] is True

        original_alert_id = first_result["alert_id"]

        connection.execute(
            """
            UPDATE security_alerts
            SET status = ?
            WHERE id = ?
            """,
            (status, original_alert_id),
        )
        connection.commit()

        second_result = detector(connection, event, rule)

        assert second_result is not None
        assert second_result["created"] is False
        assert second_result["alert_id"] == original_alert_id

        alert_count = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM security_alerts
            """
        ).fetchone()["count"]

        assert alert_count == 1

    finally:
        connection.close()


@pytest.mark.parametrize("rule_id", RULE_IDS)
@pytest.mark.parametrize("status", TERMINAL_STATUSES)
def test_terminal_alert_does_not_block_new_detection(rule_id, status):
    """
    A resolved or closed alert should not prevent a new alert
    when the same malicious activity is detected again.
    """
    connection = create_isolated_database()

    try:
        now = datetime.now(timezone.utc)
        events = build_events(rule_id, now)
        insert_events(connection, events)

        detector = get_detector(rule_id)
        rule = RULES[rule_id]
        event = events[-1]

        first_result = detector(connection, event, rule)

        assert first_result is not None
        assert first_result["created"] is True

        original_alert_id = first_result["alert_id"]

        connection.execute(
            """
            UPDATE security_alerts
            SET status = ?
            WHERE id = ?
            """,
            (status, original_alert_id),
        )
        connection.commit()

        second_result = detector(connection, event, rule)

        assert second_result is not None
        assert second_result["created"] is True
        assert second_result["alert_id"] != original_alert_id

        alert_count = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM security_alerts
            """
        ).fetchone()["count"]

        assert alert_count == 2

        original_alert = connection.execute(
            """
            SELECT status
            FROM security_alerts
            WHERE id = ?
            """,
            (original_alert_id,),
        ).fetchone()

        assert original_alert["status"] == status

        new_alert = connection.execute(
            """
            SELECT status
            FROM security_alerts
            WHERE id = ?
            """,
            (second_result["alert_id"],),
        ).fetchone()

        assert new_alert["status"] == "open"

    finally:
        connection.close()
