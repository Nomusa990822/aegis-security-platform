from datetime import datetime, timedelta, timezone

from app.detection.registry import get_detection_rules, get_detector
from app.evaluation.runner import create_isolated_database


RULES = {rule["rule_id"]: rule for rule in get_detection_rules()}


def evaluate(rule_id, events):
    connection = create_isolated_database()
    now = datetime.now(timezone.utc)

    try:
        for event in events:
            received_at = event.get("received_at", now.isoformat())
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
                    event.get("event_type", "authentication"),
                    event.get("source_ip"),
                    event.get("username"),
                    event.get("outcome"),
                    "Authentication detection test",
                    event.get("occurred_at", now.isoformat()),
                    received_at,
                    None, None, None,
                ),
            )
        connection.commit()
        return get_detector(rule_id)(connection, events[-1], RULES[rule_id])
    finally:
        connection.close()


def auth_event(source_ip, username="target-user", outcome="failure",
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


def test_distributed_password_guessing_detects_five_distinct_sources():
    events = [auth_event(f"198.51.100.{i}") for i in range(1, 6)]
    result = evaluate("AEGIS-AUTH-003", events)

    assert result is not None
    assert result["created"] is True
    assert result["distinct_source_count"] == 5
    assert result["target_username"] == "target-user"


def test_distributed_password_guessing_does_not_count_duplicate_sources():
    events = [auth_event("198.51.100.10") for _ in range(5)]
    assert evaluate("AEGIS-AUTH-003", events) is None


def test_distributed_password_guessing_requires_same_account():
    events = [
        auth_event(f"198.51.100.{i}", username=f"user-{i}")
        for i in range(1, 6)
    ]
    assert evaluate("AEGIS-AUTH-003", events) is None


def test_distributed_password_guessing_excludes_old_failures():
    events = [
        auth_event(
            f"198.51.100.{i}",
            received_offset_seconds=601 if i == 1 else 0,
        )
        for i in range(1, 6)
    ]
    assert evaluate("AEGIS-AUTH-003", events) is None


def test_success_after_failures_detects_five_failures_then_success():
    events = [auth_event("198.51.100.20") for _ in range(5)]
    events.append(auth_event("198.51.100.20", outcome="success"))
    result = evaluate("AEGIS-AUTH-004", events)

    assert result is not None
    assert result["created"] is True
    assert result["failed_attempt_count"] == 5


def test_success_after_failures_does_not_alert_below_threshold():
    events = [auth_event("198.51.100.21") for _ in range(4)]
    events.append(auth_event("198.51.100.21", outcome="success"))
    assert evaluate("AEGIS-AUTH-004", events) is None


def test_success_after_failures_requires_same_source_and_account():
    events = [auth_event("198.51.100.22") for _ in range(5)]
    events.append(auth_event("198.51.100.23", outcome="success"))
    assert evaluate("AEGIS-AUTH-004", events) is None


def test_success_after_failures_excludes_old_failures():
    events = [
        auth_event(
            "198.51.100.24",
            received_offset_seconds=601 if i == 0 else 0,
        )
        for i in range(5)
    ]
    events.append(auth_event("198.51.100.24", outcome="success"))
    assert evaluate("AEGIS-AUTH-004", events) is None
