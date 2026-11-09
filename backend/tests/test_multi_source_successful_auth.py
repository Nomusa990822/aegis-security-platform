from datetime import datetime, timedelta, timezone

from app.detection.registry import get_detection_rules, get_detector
from app.evaluation.runner import create_isolated_database


RULE_ID = "AEGIS-AUTH-005"
RULE = next(rule for rule in get_detection_rules() if rule["rule_id"] == RULE_ID)


def auth_event(source_ip, username="shared-account", outcome="success",
               received_offset_seconds=0):
    now = datetime.now(timezone.utc)
    return {
        "event_type": "authentication",
        "source_ip": source_ip,
        "username": username,
        "outcome": outcome,
        "occurred_at": now.isoformat(),
        "received_at": (
            now - timedelta(seconds=received_offset_seconds)
        ).isoformat(),
    }


def evaluate(events):
    connection = create_isolated_database()
    now = datetime.now(timezone.utc)

    try:
        for event in events:
            connection.execute(
                """
                INSERT INTO security_events (
                    event_type, source_ip, username, outcome,
                    description, occurred_at, received_at,
                    destination_ip, destination_port, protocol
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["event_type"], event["source_ip"],
                    event["username"], event["outcome"],
                    "Multi-source authentication test",
                    event["occurred_at"], event["received_at"],
                    None, None, None,
                ),
            )
        connection.commit()
        return get_detector(RULE_ID)(
            connection, events[-1], RULE
        )
    finally:
        connection.close()


def test_detects_successful_authentication_from_three_distinct_sources():
    events = [
        auth_event(f"198.51.100.{index}")
        for index in range(1, 4)
    ]

    result = evaluate(events)

    assert result is not None
    assert result["created"] is True
    assert result["distinct_source_count"] == 3
    assert result["username"] == "shared-account"


def test_duplicate_successes_from_one_source_do_not_inflate_threshold():
    events = [
        auth_event("198.51.100.10")
        for _ in range(5)
    ]

    assert evaluate(events) is None


def test_successes_for_different_accounts_are_not_combined():
    events = [
        auth_event(
            f"198.51.100.{index}",
            username=f"user-{index}",
        )
        for index in range(1, 4)
    ]

    assert evaluate(events) is None


def test_failed_authentication_events_are_not_counted():
    events = [
        auth_event(
            f"198.51.100.{index}",
            outcome="failure",
        )
        for index in range(1, 4)
    ]

    assert evaluate(events) is None


def test_old_successful_authentications_are_excluded():
    events = [
        auth_event(
            f"198.51.100.{index}",
            received_offset_seconds=601 if index == 1 else 0,
        )
        for index in range(1, 4)
    ]

    assert evaluate(events) is None


def test_missing_source_ip_or_username_does_not_alert():
    events = [
        auth_event("198.51.100.20"),
        auth_event("198.51.100.21"),
        auth_event("198.51.100.22"),
    ]
    events[-1]["source_ip"] = None

    assert evaluate(events) is None
