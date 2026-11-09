from datetime import datetime, timedelta, timezone

from app.detection.registry import get_detection_rules, get_detector
from app.evaluation.runner import create_isolated_database


RULE_ID = "AEGIS-NET-005"
RULE = next(rule for rule in get_detection_rules() if rule["rule_id"] == RULE_ID)


def network_event(
    destination_ip="198.51.100.10",
    destination_port=3389,
    source_ip="192.0.2.10",
    received_offset_seconds=0,
    event_type="network_connection",
):
    now = datetime.now(timezone.utc)
    return {
        "event_type": event_type,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "received_at": (
            now - timedelta(seconds=received_offset_seconds)
        ).isoformat(),
    }


def evaluate(events):
    connection = create_isolated_database()
    try:
        for event in events:
            connection.execute(
                """
                INSERT INTO security_events (
                    event_type, source_ip, username, outcome,
                    description, occurred_at, received_at,
                    destination_ip, destination_port, protocol
                )
                VALUES (?, ?, NULL, NULL, ?, ?, ?, ?, ?, 'tcp')
                """,
                (
                    event["event_type"],
                    event["source_ip"],
                    "Remote-service fan-out test",
                    event["received_at"],
                    event["received_at"],
                    event["destination_ip"],
                    event["destination_port"],
                ),
            )
        connection.commit()
        return get_detector(RULE_ID)(connection, events[-1], RULE)
    finally:
        connection.close()


def test_detects_fan_out_across_five_distinct_hosts_on_remote_ports():
    events = [
        network_event(
            destination_ip=f"198.51.100.{index}",
            destination_port=3389 if index % 2 else 445,
        )
        for index in range(1, 6)
    ]

    result = evaluate(events)

    assert result is not None
    assert result["created"] is True
    assert result["destination_count"] == 5
    assert result["rule_id"] == RULE_ID


def test_below_threshold_does_not_alert():
    events = [
        network_event(destination_ip=f"198.51.100.{index}")
        for index in range(1, 5)
    ]

    assert evaluate(events) is None


def test_repeated_connections_to_same_host_do_not_inflate_threshold():
    events = [
        network_event(destination_ip="198.51.100.10")
        for _ in range(8)
    ]

    assert evaluate(events) is None


def test_non_remote_administration_ports_are_ignored():
    events = [
        network_event(
            destination_ip=f"198.51.100.{index}",
            destination_port=443,
        )
        for index in range(1, 7)
    ]

    assert evaluate(events) is None


def test_events_from_different_sources_are_not_combined():
    events = [
        network_event(
            destination_ip=f"198.51.100.{index}",
            source_ip=f"192.0.2.{index}",
        )
        for index in range(1, 6)
    ]

    assert evaluate(events) is None


def test_events_outside_received_time_window_are_excluded():
    events = [
        network_event(
            destination_ip="198.51.100.1",
            received_offset_seconds=301,
        )
    ]
    events.extend(
        network_event(destination_ip=f"198.51.100.{index}")
        for index in range(2, 6)
    )

    assert evaluate(events) is None


def test_incomplete_or_wrong_event_is_ignored():
    events = [
        network_event(destination_ip=None),
        network_event(
            destination_ip="198.51.100.2",
            event_type="authentication",
        ),
    ]

    assert evaluate(events) is None


def test_existing_active_alert_is_reused():
    events = [
        network_event(destination_ip=f"198.51.100.{index}")
        for index in range(1, 6)
    ]
    connection = create_isolated_database()
    try:
        for event in events:
            connection.execute(
                """
                INSERT INTO security_events (
                    event_type, source_ip, description, occurred_at,
                    received_at, destination_ip, destination_port, protocol
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'tcp')
                """,
                (
                    event["event_type"], event["source_ip"],
                    "Remote-service fan-out test",
                    event["received_at"], event["received_at"],
                    event["destination_ip"], event["destination_port"],
                ),
            )
        connection.commit()
        first = get_detector(RULE_ID)(connection, events[-1], RULE)
        second = get_detector(RULE_ID)(connection, events[-1], RULE)
        assert first["created"] is True
        assert second["created"] is False
        assert second["alert_id"] == first["alert_id"]
    finally:
        connection.close()
