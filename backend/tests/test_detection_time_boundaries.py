
import importlib
from datetime import datetime, timedelta, timezone

from app.detection.registry import get_detection_rules, get_detector
from app.evaluation.runner import create_isolated_database


FIXED_NOW = datetime(
    2026, 11, 6, 12, 0, 0,
    tzinfo=timezone.utc,
)


class FrozenDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        if tz is None:
            return FIXED_NOW.replace(tzinfo=None)

        return FIXED_NOW.astimezone(tz)


RULES = {
    rule["rule_id"]: rule
    for rule in get_detection_rules()
}


DETECTOR_MODULES = {
    "AEGIS-AUTH-001": "app.detection.detectors.brute_force",
    "AEGIS-AUTH-002": "app.detection.detectors.password_spraying",
    "AEGIS-NET-001": "app.detection.detectors.port_scan",
    "AEGIS-NET-002": "app.detection.detectors.horizontal_scan",
    "AEGIS-NET-003": "app.detection.detectors.service_sweep",
    "AEGIS-NET-004": "app.detection.detectors.beaconing",
}


def make_event(
    *,
    event_type,
    source_ip="192.0.2.150",
    username=None,
    outcome=None,
    destination_ip=None,
    destination_port=None,
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
            occurred_at or FIXED_NOW
        ).isoformat(),
        "received_at": (
            received_at or FIXED_NOW
        ).isoformat(),
    }


def run_frozen_detection(rule_id, events, monkeypatch):
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
                    "Exact time-boundary validation",
                    event["occurred_at"],
                    event["received_at"],
                    event["destination_ip"],
                    event["destination_port"],
                    event["protocol"],
                ),
            )

        connection.commit()

        module = importlib.import_module(
            DETECTOR_MODULES[rule_id]
        )

        monkeypatch.setattr(
            module,
            "datetime",
            FrozenDateTime,
        )

        detector = get_detector(rule_id)

        return detector(
            connection,
            events[-1],
            RULES[rule_id],
        )

    finally:
        connection.close()


def test_brute_force_includes_event_exactly_at_window_boundary(
    monkeypatch,
):
    cutoff = FIXED_NOW - timedelta(minutes=5)

    events = [
        make_event(
            event_type="authentication",
            username="administrator",
            outcome="failure",
            received_at=cutoff,
        )
        for _ in range(5)
    ]

    result = run_frozen_detection(
        "AEGIS-AUTH-001",
        events,
        monkeypatch,
    )

    assert result is not None
    assert result["attempt_count"] == 5


def test_brute_force_excludes_event_one_microsecond_before_boundary(
    monkeypatch,
):
    cutoff = FIXED_NOW - timedelta(minutes=5)

    events = [
        make_event(
            event_type="authentication",
            username="administrator",
            outcome="failure",
            received_at=cutoff - timedelta(microseconds=1),
        )
    ]

    events.extend(
        make_event(
            event_type="authentication",
            username="administrator",
            outcome="failure",
            received_at=cutoff,
        )
        for _ in range(4)
    )

    assert run_frozen_detection(
        "AEGIS-AUTH-001",
        events,
        monkeypatch,
    ) is None


def test_password_spraying_includes_event_exactly_at_window_boundary(
    monkeypatch,
):
    cutoff = FIXED_NOW - timedelta(minutes=5)

    events = [
        make_event(
            event_type="authentication",
            username=f"user_{i}",
            outcome="failure",
            occurred_at=cutoff,
        )
        for i in range(5)
    ]

    result = run_frozen_detection(
        "AEGIS-AUTH-002",
        events,
        monkeypatch,
    )

    assert result is not None
    assert result["targeted_account_count"] == 5


def test_password_spraying_excludes_event_before_window_boundary(
    monkeypatch,
):
    cutoff = FIXED_NOW - timedelta(minutes=5)

    events = [
        make_event(
            event_type="authentication",
            username="old_user",
            outcome="failure",
            occurred_at=cutoff - timedelta(microseconds=1),
        )
    ]

    events.extend(
        make_event(
            event_type="authentication",
            username=f"user_{i}",
            outcome="failure",
            occurred_at=cutoff,
        )
        for i in range(4)
    )

    assert run_frozen_detection(
        "AEGIS-AUTH-002",
        events,
        monkeypatch,
    ) is None


def test_port_scan_includes_event_exactly_at_window_boundary(
    monkeypatch,
):
    cutoff = FIXED_NOW - timedelta(minutes=2)

    events = [
        make_event(
            event_type="network_connection",
            destination_ip="198.51.100.150",
            destination_port=20000 + i,
            received_at=cutoff,
        )
        for i in range(10)
    ]

    result = run_frozen_detection(
        "AEGIS-NET-001",
        events,
        monkeypatch,
    )

    assert result is not None
    assert result["distinct_port_count"] == 10


def test_port_scan_excludes_event_before_window_boundary(
    monkeypatch,
):
    cutoff = FIXED_NOW - timedelta(minutes=2)

    events = [
        make_event(
            event_type="network_connection",
            destination_ip="198.51.100.150",
            destination_port=20000,
            received_at=cutoff - timedelta(microseconds=1),
        )
    ]

    events.extend(
        make_event(
            event_type="network_connection",
            destination_ip="198.51.100.150",
            destination_port=20000 + i,
            received_at=cutoff,
        )
        for i in range(1, 10)
    )

    assert run_frozen_detection(
        "AEGIS-NET-001",
        events,
        monkeypatch,
    ) is None


def test_horizontal_scan_includes_event_exactly_at_window_boundary(
    monkeypatch,
):
    cutoff = FIXED_NOW - timedelta(minutes=2)

    events = [
        make_event(
            event_type="network_connection",
            destination_ip=f"198.51.100.{i + 1}",
            destination_port=443,
            received_at=cutoff,
        )
        for i in range(10)
    ]

    result = run_frozen_detection(
        "AEGIS-NET-002",
        events,
        monkeypatch,
    )

    assert result is not None
    assert result["destination_count"] == 10


def test_horizontal_scan_excludes_event_before_window_boundary(
    monkeypatch,
):
    cutoff = FIXED_NOW - timedelta(minutes=2)

    events = [
        make_event(
            event_type="network_connection",
            destination_ip="198.51.100.1",
            destination_port=443,
            received_at=cutoff - timedelta(microseconds=1),
        )
    ]

    events.extend(
        make_event(
            event_type="network_connection",
            destination_ip=f"198.51.100.{i + 1}",
            destination_port=443,
            received_at=cutoff,
        )
        for i in range(1, 10)
    )

    assert run_frozen_detection(
        "AEGIS-NET-002",
        events,
        monkeypatch,
    ) is None


def test_service_sweep_includes_event_exactly_at_window_boundary(
    monkeypatch,
):
    cutoff = FIXED_NOW - timedelta(minutes=5)

    events = [
        make_event(
            event_type="network_connection",
            destination_ip=f"198.51.100.{host}",
            destination_port=8000 + port,
            received_at=cutoff,
        )
        for host in range(1, 6)
        for port in range(4)
    ]

    result = run_frozen_detection(
        "AEGIS-NET-003",
        events,
        monkeypatch,
    )

    assert result is not None
    assert result["destination_pair_count"] == 20


def test_service_sweep_excludes_event_before_window_boundary(
    monkeypatch,
):
    cutoff = FIXED_NOW - timedelta(minutes=5)

    events = [
        make_event(
            event_type="network_connection",
            destination_ip="198.51.100.1",
            destination_port=8000,
            received_at=cutoff - timedelta(microseconds=1),
        )
    ]

    remaining_pairs = [
        (host, port)
        for host in range(1, 6)
        for port in range(4)
        if not (host == 1 and port == 0)
    ]

    events.extend(
        make_event(
            event_type="network_connection",
            destination_ip=f"198.51.100.{host}",
            destination_port=8000 + port,
            received_at=cutoff,
        )
        for host, port in remaining_pairs
    )

    assert run_frozen_detection(
        "AEGIS-NET-003",
        events,
        monkeypatch,
    ) is None


def test_beaconing_includes_connection_exactly_at_window_boundary(
    monkeypatch,
):
    cutoff = FIXED_NOW - timedelta(minutes=10)

    events = [
        make_event(
            event_type="network_connection",
            destination_ip="198.51.100.160",
            destination_port=443,
            occurred_at=cutoff + timedelta(seconds=120 * i),
        )
        for i in range(6)
    ]

    result = run_frozen_detection(
        "AEGIS-NET-004",
        events,
        monkeypatch,
    )

    assert result is not None
    assert result["connection_count"] == 6


def test_beaconing_excludes_connection_before_window_boundary(
    monkeypatch,
):
    cutoff = FIXED_NOW - timedelta(minutes=10)

    events = [
        make_event(
            event_type="network_connection",
            destination_ip="198.51.100.160",
            destination_port=443,
            occurred_at=cutoff - timedelta(microseconds=1),
        )
    ]

    events.extend(
        make_event(
            event_type="network_connection",
            destination_ip="198.51.100.160",
            destination_port=443,
            occurred_at=cutoff + timedelta(seconds=120 * i),
        )
        for i in range(1, 6)
    )

    assert run_frozen_detection(
        "AEGIS-NET-004",
        events,
        monkeypatch,
    ) is None


def test_password_spraying_uses_chronological_order_for_mixed_offsets(
    monkeypatch,
):
    cutoff = FIXED_NOW - timedelta(minutes=5)
    events = [
        make_event(
            event_type="authentication",
            username="too_old_user",
            outcome="failure",
            occurred_at=(cutoff - timedelta(minutes=1)).astimezone(
                timezone(timedelta(hours=2))
            ),
        )
    ]
    events.extend(
        make_event(
            event_type="authentication",
            username=f"user_{index}",
            outcome="failure",
            occurred_at=cutoff.astimezone(
                timezone(timedelta(hours=2))
            ),
        )
        for index in range(4)
    )

    assert run_frozen_detection(
        "AEGIS-AUTH-002",
        events,
        monkeypatch,
    ) is None


def test_password_spraying_includes_in_window_mixed_offset_timestamp(
    monkeypatch,
):
    cutoff = FIXED_NOW - timedelta(minutes=5)
    events = [
        make_event(
            event_type="authentication",
            username="offset_user",
            outcome="failure",
            occurred_at=(cutoff + timedelta(seconds=1)).astimezone(
                timezone(timedelta(hours=-5))
            ),
        )
    ]
    events.extend(
        make_event(
            event_type="authentication",
            username=f"user_{index}",
            outcome="failure",
            occurred_at=cutoff,
        )
        for index in range(4)
    )

    result = run_frozen_detection(
        "AEGIS-AUTH-002",
        events,
        monkeypatch,
    )
    assert result is not None
    assert result["targeted_account_count"] == 5


def test_beaconing_orders_mixed_offsets_chronologically(monkeypatch):
    offsets = (2, -5, 5, -2, 3, -4)
    events = []
    for index, offset in enumerate(offsets):
        occurred_at = (
            FIXED_NOW - timedelta(minutes=9) + timedelta(seconds=90 * index)
        ).astimezone(timezone(timedelta(hours=offset)))
        events.append(
            make_event(
                event_type="network_connection",
                destination_ip="198.51.100.160",
                destination_port=443,
                occurred_at=occurred_at,
            )
        )

    result = run_frozen_detection(
        "AEGIS-NET-004",
        events,
        monkeypatch,
    )
    assert result is not None
    assert result["connection_count"] == 6
