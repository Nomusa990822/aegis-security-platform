
from datetime import datetime, timedelta, timezone

import pytest

from app.detection.registry import get_detection_rules, get_detector
from app.evaluation.runner import create_isolated_database


RULES = {
    rule["rule_id"]: rule
    for rule in get_detection_rules()
}


def make_event(
    event_type="network_connection",
    source_ip="192.0.2.100",
    username=None,
    outcome=None,
    destination_ip="198.51.100.100",
    destination_port=443,
    occurred_offset_seconds=0,
    received_offset_seconds=0,
):
    now = datetime.now(timezone.utc)

    return {
        "event_type": event_type,
        "source_ip": source_ip,
        "username": username,
        "outcome": outcome,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "protocol": "tcp",
        "occurred_at": (
            now - timedelta(seconds=occurred_offset_seconds)
        ).isoformat(),
        "received_at": (
            now - timedelta(seconds=received_offset_seconds)
        ).isoformat(),
    }


def evaluate(rule_id, events):
    """
    Insert synthetic events into an isolated in-memory database
    and invoke one actual production detector.
    """

    connection = create_isolated_database()

    try:
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
                    "Adversarial validation event",
                    event["occurred_at"],
                    event["received_at"],
                    event["destination_ip"],
                    event["destination_port"],
                    event["protocol"],
                ),
            )

        connection.commit()

        detector = get_detector(rule_id)

        return detector(
            connection,
            events[-1],
            RULES[rule_id],
        )

    finally:
        connection.close()


# ============================================================
# 1. THRESHOLD BOUNDARY VALIDATION
# ============================================================


def test_brute_force_threshold_below_boundary():
    events = [
        make_event(
            event_type="authentication",
            username="administrator",
            outcome="failure",
        )
        for _ in range(4)
    ]

    assert evaluate("AEGIS-AUTH-001", events) is None


def test_brute_force_threshold_at_boundary():
    events = [
        make_event(
            event_type="authentication",
            username="administrator",
            outcome="failure",
        )
        for _ in range(5)
    ]

    result = evaluate("AEGIS-AUTH-001", events)

    assert result is not None
    assert result["attempt_count"] == 5


def test_password_spraying_threshold_below_boundary():
    events = [
        make_event(
            event_type="authentication",
            username=f"user_{i}",
            outcome="failure",
        )
        for i in range(4)
    ]

    assert evaluate("AEGIS-AUTH-002", events) is None


def test_password_spraying_threshold_at_boundary():
    events = [
        make_event(
            event_type="authentication",
            username=f"user_{i}",
            outcome="failure",
        )
        for i in range(5)
    ]

    result = evaluate("AEGIS-AUTH-002", events)

    assert result is not None
    assert result["targeted_account_count"] == 5


def test_port_scan_threshold_below_boundary():
    events = [
        make_event(destination_port=20000 + i)
        for i in range(9)
    ]

    assert evaluate("AEGIS-NET-001", events) is None


def test_port_scan_threshold_at_boundary():
    events = [
        make_event(destination_port=20000 + i)
        for i in range(10)
    ]

    result = evaluate("AEGIS-NET-001", events)

    assert result is not None
    assert result["distinct_port_count"] == 10


def test_horizontal_scan_threshold_below_boundary():
    events = [
        make_event(
            destination_ip=f"198.51.100.{i + 1}",
            destination_port=443,
        )
        for i in range(9)
    ]

    assert evaluate("AEGIS-NET-002", events) is None


def test_horizontal_scan_threshold_at_boundary():
    events = [
        make_event(
            destination_ip=f"198.51.100.{i + 1}",
            destination_port=443,
        )
        for i in range(10)
    ]

    result = evaluate("AEGIS-NET-002", events)

    assert result is not None
    assert result["destination_count"] == 10


def test_service_sweep_threshold_below_boundary():
    events = [
        make_event(
            destination_ip=f"198.51.100.{host}",
            destination_port=8000 + port,
        )
        for host in range(1, 5)
        for port in range(4)
    ]

    assert len(events) == 16
    assert evaluate("AEGIS-NET-003", events) is None


def test_service_sweep_threshold_at_boundary():
    events = [
        make_event(
            destination_ip=f"198.51.100.{host}",
            destination_port=8000 + port,
        )
        for host in range(1, 6)
        for port in range(4)
    ]

    assert len(events) == 20

    result = evaluate("AEGIS-NET-003", events)

    assert result is not None
    assert result["destination_pair_count"] == 20


def test_beaconing_threshold_below_boundary():
    events = [
        make_event(
            occurred_offset_seconds=60 - (i * 15),
        )
        for i in range(5)
    ]

    assert evaluate("AEGIS-NET-004", events) is None


def test_beaconing_threshold_at_boundary():
    events = [
        make_event(
            occurred_offset_seconds=75 - (i * 15),
        )
        for i in range(6)
    ]

    result = evaluate("AEGIS-NET-004", events)

    assert result is not None
    assert result["connection_count"] == 6


# ============================================================
# 2. TIME-WINDOW VALIDATION
# ============================================================


def test_brute_force_ignores_events_outside_received_time_window():
    events = [
        make_event(
            event_type="authentication",
            username="administrator",
            outcome="failure",
            received_offset_seconds=301,
        )
    ]

    events.extend(
        make_event(
            event_type="authentication",
            username="administrator",
            outcome="failure",
        )
        for _ in range(4)
    )

    assert evaluate("AEGIS-AUTH-001", events) is None


def test_password_spraying_ignores_events_outside_occurred_time_window():
    events = [
        make_event(
            event_type="authentication",
            username="old_user",
            outcome="failure",
            occurred_offset_seconds=301,
        )
    ]

    events.extend(
        make_event(
            event_type="authentication",
            username=f"user_{i}",
            outcome="failure",
        )
        for i in range(4)
    )

    assert evaluate("AEGIS-AUTH-002", events) is None


def test_port_scan_ignores_events_outside_received_time_window():
    events = [
        make_event(
            destination_port=20000,
            received_offset_seconds=121,
        )
    ]

    events.extend(
        make_event(destination_port=20000 + i)
        for i in range(1, 10)
    )

    assert evaluate("AEGIS-NET-001", events) is None


def test_beaconing_rejects_old_events_outside_occurred_time_window():
    events = [
        make_event(
            occurred_offset_seconds=601,
        )
    ]

    events.extend(
        make_event(
            occurred_offset_seconds=75 - (i * 15),
        )
        for i in range(5)
    )

    assert evaluate("AEGIS-NET-004", events) is None


# ============================================================
# 3. DUPLICATE EVENT VALIDATION
# ============================================================


def test_duplicate_port_events_do_not_inflate_distinct_port_count():
    events = [
        make_event(destination_port=443)
        for _ in range(10)
    ]

    assert evaluate("AEGIS-NET-001", events) is None


def test_duplicate_destination_events_do_not_inflate_horizontal_scan():
    events = [
        make_event(
            destination_ip="198.51.100.100",
            destination_port=443,
        )
        for _ in range(10)
    ]

    assert evaluate("AEGIS-NET-002", events) is None


def test_duplicate_service_pairs_do_not_inflate_service_sweep():
    events = [
        make_event(
            destination_ip="198.51.100.100",
            destination_port=443,
        )
        for _ in range(20)
    ]

    assert evaluate("AEGIS-NET-003", events) is None


def test_duplicate_usernames_do_not_inflate_password_spraying():
    events = [
        make_event(
            event_type="authentication",
            username="administrator",
            outcome="failure",
        )
        for _ in range(5)
    ]

    assert evaluate("AEGIS-AUTH-002", events) is None


def test_brute_force_currently_counts_duplicate_event_rows():
    """
    Known limitation:
    brute-force detection counts rows, not unique authentication
    events. Five duplicate rows currently satisfy its threshold.

    This test documents current behaviour; it does not establish
    that duplicate events should be considered independent attempts.
    """

    events = [
        make_event(
            event_type="authentication",
            username="administrator",
            outcome="failure",
        )
        for _ in range(5)
    ]

    result = evaluate("AEGIS-AUTH-001", events)

    assert result is not None
    assert result["attempt_count"] == 5


# ============================================================
# 4. OVERLAPPING ATTACK VALIDATION
# ============================================================


def test_repeated_failures_against_one_account_trigger_brute_force_only():
    events = [
        make_event(
            event_type="authentication",
            username="administrator",
            outcome="failure",
        )
        for _ in range(5)
    ]

    brute_force = evaluate("AEGIS-AUTH-001", events)
    password_spraying = evaluate("AEGIS-AUTH-002", events)

    assert brute_force is not None
    assert password_spraying is None


def test_failures_against_distinct_accounts_trigger_spraying_only():
    events = [
        make_event(
            event_type="authentication",
            username=f"user_{i}",
            outcome="failure",
        )
        for i in range(5)
    ]

    brute_force = evaluate("AEGIS-AUTH-001", events)
    password_spraying = evaluate("AEGIS-AUTH-002", events)

    assert brute_force is None
    assert password_spraying is not None


def test_service_sweep_pattern_does_not_trigger_port_or_horizontal_scan():
    events = [
        make_event(
            destination_ip=f"198.51.100.{host}",
            destination_port=8000 + port,
        )
        for host in range(1, 6)
        for port in range(4)
    ]

    service_sweep = evaluate("AEGIS-NET-003", events)
    port_scan = evaluate("AEGIS-NET-001", events)
    horizontal_scan = evaluate("AEGIS-NET-002", events)

    assert service_sweep is not None
    assert port_scan is None
    assert horizontal_scan is None


# ============================================================
# 5. INCOMPLETE TELEMETRY VALIDATION
# ============================================================


@pytest.mark.parametrize(
    "rule_id,event",
    [
        (
            "AEGIS-NET-001",
            make_event(destination_ip=None),
        ),
        (
            "AEGIS-NET-001",
            make_event(destination_port=None),
        ),
        (
            "AEGIS-NET-002",
            make_event(destination_ip=None),
        ),
        (
            "AEGIS-NET-002",
            make_event(destination_port=None),
        ),
        (
            "AEGIS-NET-003",
            make_event(destination_ip=None),
        ),
        (
            "AEGIS-NET-003",
            make_event(destination_port=None),
        ),
        (
            "AEGIS-NET-004",
            make_event(destination_ip=None),
        ),
    ],
)
def test_network_detectors_ignore_incomplete_telemetry(rule_id, event):
    assert evaluate(rule_id, [event]) is None


def test_brute_force_ignores_missing_username():
    event = make_event(
        event_type="authentication",
        username=None,
        outcome="failure",
    )

    assert evaluate("AEGIS-AUTH-001", [event]) is None


def test_password_spraying_ignores_missing_username():
    event = make_event(
        event_type="authentication",
        username=None,
        outcome="failure",
    )

    assert evaluate("AEGIS-AUTH-002", [event]) is None


def test_password_spraying_handles_missing_outcome():
    event = make_event(
        event_type="authentication",
        username="administrator",
        outcome=None,
    )

    assert evaluate("AEGIS-AUTH-002", [event]) is None


# ============================================================
# 6. NOISY BENIGN TRAFFIC VALIDATION
# ============================================================


def test_successful_authentication_does_not_trigger_brute_force():
    events = [
        make_event(
            event_type="authentication",
            username="normal_user",
            outcome="success",
        )
        for _ in range(10)
    ]

    assert evaluate("AEGIS-AUTH-001", events) is None


def test_successful_authentication_does_not_trigger_password_spraying():
    events = [
        make_event(
            event_type="authentication",
            username=f"user_{i}",
            outcome="success",
        )
        for i in range(10)
    ]

    assert evaluate("AEGIS-AUTH-002", events) is None


def test_small_number_of_ports_does_not_trigger_port_scan():
    events = [
        make_event(destination_port=port)
        for port in [80, 443, 8080]
    ]

    assert evaluate("AEGIS-NET-001", events) is None


def test_small_number_of_hosts_does_not_trigger_horizontal_scan():
    events = [
        make_event(
            destination_ip=f"198.51.100.{i}",
            destination_port=443,
        )
        for i in range(1, 4)
    ]

    assert evaluate("AEGIS-NET-002", events) is None


def test_small_number_of_service_pairs_does_not_trigger_service_sweep():
    events = [
        make_event(
            destination_ip="198.51.100.10",
            destination_port=80,
        ),
        make_event(
            destination_ip="198.51.100.10",
            destination_port=443,
        ),
        make_event(
            destination_ip="198.51.100.11",
            destination_port=80,
        ),
        make_event(
            destination_ip="198.51.100.11",
            destination_port=443,
        ),
    ]

    assert evaluate("AEGIS-NET-003", events) is None


def test_irregular_connection_intervals_do_not_trigger_beaconing():
    offsets = [85, 80, 65, 60, 15, 0]

    events = [
        make_event(
            occurred_offset_seconds=offset,
        )
        for offset in offsets
    ]

    assert evaluate("AEGIS-NET-004", events) is None
