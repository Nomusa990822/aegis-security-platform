
from datetime import datetime, timedelta, timezone

import pytest

from app.detection.registry import get_detection_rules, get_detector
from app.evaluation.runner import create_isolated_database


RULES = {
    rule["rule_id"]: rule
    for rule in get_detection_rules()
}


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
                "Alert scope isolation validation event",
                event["occurred_at"],
                event["received_at"],
                event["destination_ip"],
                event["destination_port"],
                event["protocol"],
            ),
        )

    connection.commit()


def detect(connection, rule_id, events):
    detector = get_detector(rule_id)

    return detector(
        connection,
        events[-1],
        RULES[rule_id],
    )


def alert_count(connection):
    return connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM security_alerts
        """
    ).fetchone()["count"]


def make_brute_force_events(now, username, source_ip):
    return [
        make_event(
            now,
            event_type="authentication",
            source_ip=source_ip,
            username=username,
            outcome="failure",
        )
        for _ in range(5)
    ]


def make_spraying_events(now, source_ip):
    return [
        make_event(
            now,
            event_type="authentication",
            source_ip=source_ip,
            username=f"user_{index}",
            outcome="failure",
        )
        for index in range(5)
    ]


def make_port_scan_events(now, destination_ip):
    return [
        make_event(
            now,
            destination_ip=destination_ip,
            destination_port=20000 + index,
        )
        for index in range(10)
    ]


def make_horizontal_scan_events(now, destination_port):
    return [
        make_event(
            now,
            destination_ip=f"198.51.100.{index + 1}",
            destination_port=destination_port,
        )
        for index in range(10)
    ]


def make_service_sweep_events(now, source_ip, host_prefix):
    events = []

    for host in range(1, 6):
        for port in range(4):
            events.append(
                make_event(
                    now,
                    source_ip=source_ip,
                    destination_ip=f"{host_prefix}.{host}",
                    destination_port=8000 + port,
                )
            )

    return events


def make_beaconing_events(now, destination_ip):
    return [
        make_event(
            now,
            destination_ip=destination_ip,
            occurred_at=now - timedelta(
                seconds=60 * (5 - index)
            ),
        )
        for index in range(6)
    ]


def assert_separate_alerts(
    connection,
    first_result,
    second_result,
):
    assert first_result is not None
    assert second_result is not None

    assert first_result["created"] is True
    assert second_result["created"] is True

    assert first_result["alert_id"] != second_result["alert_id"]
    assert alert_count(connection) == 2


def test_brute_force_alerts_are_scoped_by_username():
    connection = create_isolated_database()

    try:
        now = datetime.now(timezone.utc)

        first_events = make_brute_force_events(
            now,
            "administrator",
            "198.51.100.100",
        )
        second_events = make_brute_force_events(
            now,
            "service_account",
            "198.51.100.100",
        )

        insert_events(
            connection,
            first_events + second_events,
        )

        first_result = detect(
            connection,
            "AEGIS-AUTH-001",
            first_events,
        )
        second_result = detect(
            connection,
            "AEGIS-AUTH-001",
            second_events,
        )

        assert_separate_alerts(
            connection,
            first_result,
            second_result,
        )

    finally:
        connection.close()


def test_port_scan_alerts_are_scoped_by_destination_ip():
    connection = create_isolated_database()

    try:
        now = datetime.now(timezone.utc)

        first_events = make_port_scan_events(
            now,
            "198.51.100.10",
        )
        second_events = make_port_scan_events(
            now,
            "198.51.100.20",
        )

        insert_events(
            connection,
            first_events + second_events,
        )

        first_result = detect(
            connection,
            "AEGIS-NET-001",
            first_events,
        )
        second_result = detect(
            connection,
            "AEGIS-NET-001",
            second_events,
        )

        assert_separate_alerts(
            connection,
            first_result,
            second_result,
        )

    finally:
        connection.close()


def test_horizontal_scan_alerts_are_scoped_by_destination_port():
    connection = create_isolated_database()

    try:
        now = datetime.now(timezone.utc)

        first_events = make_horizontal_scan_events(now, 443)
        second_events = make_horizontal_scan_events(now, 22)

        insert_events(
            connection,
            first_events + second_events,
        )

        first_result = detect(
            connection,
            "AEGIS-NET-002",
            first_events,
        )
        second_result = detect(
            connection,
            "AEGIS-NET-002",
            second_events,
        )

        assert_separate_alerts(
            connection,
            first_result,
            second_result,
        )

    finally:
        connection.close()


def test_password_spraying_alerts_are_scoped_by_source_ip():
    connection = create_isolated_database()

    try:
        now = datetime.now(timezone.utc)

        first_events = make_spraying_events(
            now,
            "198.51.100.100",
        )
        second_events = make_spraying_events(
            now,
            "198.51.100.200",
        )

        insert_events(
            connection,
            first_events + second_events,
        )

        first_result = detect(
            connection,
            "AEGIS-AUTH-002",
            first_events,
        )
        second_result = detect(
            connection,
            "AEGIS-AUTH-002",
            second_events,
        )

        assert_separate_alerts(
            connection,
            first_result,
            second_result,
        )

    finally:
        connection.close()


def test_service_sweep_alerts_are_scoped_by_source_ip():
    connection = create_isolated_database()

    try:
        now = datetime.now(timezone.utc)

        first_events = make_service_sweep_events(
            now,
            "198.51.100.100",
            "203.0.113",
        )
        second_events = make_service_sweep_events(
            now,
            "198.51.100.200",
            "192.0.2",
        )

        insert_events(
            connection,
            first_events + second_events,
        )

        first_result = detect(
            connection,
            "AEGIS-NET-003",
            first_events,
        )
        second_result = detect(
            connection,
            "AEGIS-NET-003",
            second_events,
        )

        assert_separate_alerts(
            connection,
            first_result,
            second_result,
        )

    finally:
        connection.close()


def test_beaconing_alerts_are_scoped_by_destination_ip():
    connection = create_isolated_database()

    try:
        now = datetime.now(timezone.utc)

        first_events = make_beaconing_events(
            now,
            "203.0.113.10",
        )
        second_events = make_beaconing_events(
            now,
            "203.0.113.20",
        )

        insert_events(
            connection,
            first_events + second_events,
        )

        first_result = detect(
            connection,
            "AEGIS-NET-004",
            first_events,
        )
        second_result = detect(
            connection,
            "AEGIS-NET-004",
            second_events,
        )

        assert_separate_alerts(
            connection,
            first_result,
            second_result,
        )

    finally:
        connection.close()


def test_different_detection_rules_do_not_share_alerts():
    """
    Brute force and password spraying can originate from the
    same source IP but represent different detection rules.
    """
    connection = create_isolated_database()

    try:
        now = datetime.now(timezone.utc)
        source_ip = "198.51.100.100"

        brute_force_events = make_brute_force_events(
            now,
            "administrator",
            source_ip,
        )
        spraying_events = make_spraying_events(
            now,
            source_ip,
        )

        insert_events(
            connection,
            brute_force_events + spraying_events,
        )

        brute_force_result = detect(
            connection,
            "AEGIS-AUTH-001",
            brute_force_events,
        )
        spraying_result = detect(
            connection,
            "AEGIS-AUTH-002",
            spraying_events,
        )

        assert_separate_alerts(
            connection,
            brute_force_result,
            spraying_result,
        )

        assert brute_force_result["rule_id"] == "AEGIS-AUTH-001"
        assert spraying_result["rule_id"] == "AEGIS-AUTH-002"

    finally:
        connection.close()
