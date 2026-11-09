from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional


@dataclass
class Scenario:
    scenario_id: str
    name: str
    category: str
    expected_rule_id: Optional[str]
    events: list[dict]


def create_event(
    event_type: str,
    occurred_at: datetime,
    source_ip: str,
    username: Optional[str] = None,
    outcome: Optional[str] = None,
    destination_ip: Optional[str] = None,
    destination_port: Optional[int] = None,
    protocol: Optional[str] = None,
) -> dict:
    return {
        "event_type": event_type,
        "source_ip": source_ip,
        "username": username,
        "outcome": outcome,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "protocol": protocol,
        "occurred_at": occurred_at.isoformat(),
    }


def build_scenarios(
    base_time: Optional[datetime] = None,
) -> list[Scenario]:
    """
    Build a labelled synthetic detection dataset.

    Each malicious scenario targets one detection rule.
    Benign scenarios provide negative examples for every rule.
    """

    if base_time is None:
        base_time = datetime.now(timezone.utc)

    if base_time.tzinfo is None:
        base_time = base_time.replace(tzinfo=timezone.utc)

    scenarios = []

    # ---------------------------------------------------------
    # MALICIOUS SCENARIO 1: BRUTE FORCE
    # ---------------------------------------------------------

    events = [
        create_event(
            event_type="authentication",
            occurred_at=base_time - timedelta(seconds=10 * i),
            source_ip="192.0.2.10",
            username="administrator",
            outcome="failure",
        )
        for i in range(5)
    ]

    scenarios.append(
        Scenario(
            scenario_id="MAL-001",
            name="Repeated authentication failures",
            category="malicious",
            expected_rule_id="AEGIS-AUTH-001",
            events=events,
        )
    )

    # ---------------------------------------------------------
    # MALICIOUS SCENARIO 2: PASSWORD SPRAYING
    # ---------------------------------------------------------

    events = [
        create_event(
            event_type="authentication",
            occurred_at=base_time - timedelta(seconds=10 * i),
            source_ip="192.0.2.20",
            username=f"user_{i}",
            outcome="failure",
        )
        for i in range(5)
    ]

    scenarios.append(
        Scenario(
            scenario_id="MAL-002",
            name="Authentication failures against multiple accounts",
            category="malicious",
            expected_rule_id="AEGIS-AUTH-002",
            events=events,
        )
    )

    # ---------------------------------------------------------
    # MALICIOUS SCENARIO 3: PORT SCANNING
    # ---------------------------------------------------------

    events = [
        create_event(
            event_type="network_connection",
            occurred_at=base_time - timedelta(seconds=i),
            source_ip="192.0.2.30",
            destination_ip="198.51.100.10",
            destination_port=20000 + i,
            protocol="tcp",
        )
        for i in range(10)
    ]

    scenarios.append(
        Scenario(
            scenario_id="MAL-003",
            name="Multiple destination ports on one host",
            category="malicious",
            expected_rule_id="AEGIS-NET-001",
            events=events,
        )
    )

    # ---------------------------------------------------------
    # MALICIOUS SCENARIO 4: HORIZONTAL SCANNING
    # ---------------------------------------------------------

    events = [
        create_event(
            event_type="network_connection",
            occurred_at=base_time - timedelta(seconds=i),
            source_ip="192.0.2.40",
            destination_ip=f"198.51.100.{i + 1}",
            destination_port=443,
            protocol="tcp",
        )
        for i in range(10)
    ]

    scenarios.append(
        Scenario(
            scenario_id="MAL-004",
            name="Same destination port across multiple hosts",
            category="malicious",
            expected_rule_id="AEGIS-NET-002",
            events=events,
        )
    )

    # ---------------------------------------------------------
    # MALICIOUS SCENARIO 5: SERVICE SWEEP
    # ---------------------------------------------------------

    events = []

    for host_number in range(1, 6):
        for port in range(8000, 8004):
            events.append(
                create_event(
                    event_type="network_connection",
                    occurred_at=base_time - timedelta(
                        seconds=len(events)
                    ),
                    source_ip="192.0.2.50",
                    destination_ip=f"198.51.100.{host_number}",
                    destination_port=port,
                    protocol="tcp",
                )
            )

    scenarios.append(
        Scenario(
            scenario_id="MAL-005",
            name="Multi-target service discovery",
            category="malicious",
            expected_rule_id="AEGIS-NET-003",
            events=events,
        )
    )

    # ---------------------------------------------------------
    # MALICIOUS SCENARIO 6: BEACONING
    # ---------------------------------------------------------

    beacon_offsets = [-75, -60, -45, -30, -15, 0]

    events = [
        create_event(
            event_type="network_connection",
            occurred_at=base_time + timedelta(seconds=offset),
            source_ip="192.0.2.60",
            destination_ip="198.51.100.60",
            destination_port=443,
            protocol="tcp",
        )
        for offset in beacon_offsets
    ]

    scenarios.append(
        Scenario(
            scenario_id="MAL-006",
            name="Regular repeated outbound connections",
            category="malicious",
            expected_rule_id="AEGIS-NET-004",
            events=events,
        )
    )

    # ---------------------------------------------------------
    # MALICIOUS SCENARIO 7: DISTRIBUTED PASSWORD GUESSING
    # ---------------------------------------------------------

    events = [
        create_event(
            event_type="authentication",
            occurred_at=base_time - timedelta(seconds=10 * i),
            source_ip=f"192.0.2.{80 + i}",
            username="finance-admin",
            outcome="failure",
        )
        for i in range(5)
    ]

    scenarios.append(
        Scenario(
            scenario_id="MAL-007",
            name="One account targeted by failures from multiple source IPs",
            category="malicious",
            expected_rule_id="AEGIS-AUTH-003",
            events=events,
        )
    )

    # ---------------------------------------------------------
    # MALICIOUS SCENARIO 8: SUCCESS AFTER REPEATED FAILURES
    # ---------------------------------------------------------

    events = [
        create_event(
            event_type="authentication",
            occurred_at=base_time - timedelta(seconds=60 - (10 * i)),
            source_ip="192.0.2.88",
            username="payroll-admin",
            outcome="failure",
        )
        for i in range(5)
    ]
    events.append(
        create_event(
            event_type="authentication",
            occurred_at=base_time,
            source_ip="192.0.2.88",
            username="payroll-admin",
            outcome="success",
        )
    )

    scenarios.append(
        Scenario(
            scenario_id="MAL-008",
            name="Successful authentication after repeated failures",
            category="malicious",
            expected_rule_id="AEGIS-AUTH-004",
            events=events,
        )
    )

    # ---------------------------------------------------------
    # MALICIOUS SCENARIO 9: MULTI-SOURCE SUCCESSFUL AUTHENTICATION
    # ---------------------------------------------------------

    events = [
        create_event(
            event_type="authentication",
            occurred_at=base_time - timedelta(seconds=10 * i),
            source_ip=f"192.0.2.{90 + i}",
            username="operations-account",
            outcome="success",
        )
        for i in range(3)
    ]

    scenarios.append(
        Scenario(
            scenario_id="MAL-009",
            name="Successful authentication to one account from multiple source IPs",
            category="malicious",
            expected_rule_id="AEGIS-AUTH-005",
            events=events,
        )
    )

    # ---------------------------------------------------------
    # MALICIOUS SCENARIO 10: REMOTE-SERVICE CONNECTION FAN-OUT
    # ---------------------------------------------------------

    events = [
        create_event(
            event_type="network_connection",
            occurred_at=base_time - timedelta(seconds=10 * i),
            source_ip="192.0.2.110",
            destination_ip=f"198.51.100.{110 + i}",
            destination_port=3389 if i % 2 else 445,
            protocol="tcp",
        )
        for i in range(5)
    ]

    scenarios.append(
        Scenario(
            scenario_id="MAL-010",
            name="Remote-administration port fan-out across multiple hosts",
            category="malicious",
            expected_rule_id="AEGIS-NET-005",
            events=events,
        )
    )

    # ---------------------------------------------------------
    # BENIGN SCENARIO 1: SUCCESSFUL AUTHENTICATION
    # ---------------------------------------------------------

    events = [
        create_event(
            event_type="authentication",
            occurred_at=base_time - timedelta(seconds=10 * i),
            source_ip="192.0.2.70",
            username="normal_user",
            outcome="success",
        )
        for i in range(6)
    ]

    scenarios.append(
        Scenario(
            scenario_id="BEN-001",
            name="Repeated successful authentication",
            category="benign",
            expected_rule_id=None,
            events=events,
        )
    )

    # ---------------------------------------------------------
    # BENIGN SCENARIO 2: LOW-VOLUME AUTHENTICATION FAILURES
    # ---------------------------------------------------------

    events = [
        create_event(
            event_type="authentication",
            occurred_at=base_time - timedelta(seconds=10 * i),
            source_ip="192.0.2.71",
            username="normal_user",
            outcome="failure",
        )
        for i in range(3)
    ]

    scenarios.append(
        Scenario(
            scenario_id="BEN-002",
            name="Small number of authentication failures",
            category="benign",
            expected_rule_id=None,
            events=events,
        )
    )

    # ---------------------------------------------------------
    # BENIGN SCENARIO 3: LOW-VOLUME PORT ACTIVITY
    # ---------------------------------------------------------

    events = [
        create_event(
            event_type="network_connection",
            occurred_at=base_time - timedelta(seconds=i),
            source_ip="192.0.2.72",
            destination_ip="198.51.100.72",
            destination_port=port,
            protocol="tcp",
        )
        for i, port in enumerate([80, 443, 8080])
    ]

    scenarios.append(
        Scenario(
            scenario_id="BEN-003",
            name="Routine connections to a small number of ports",
            category="benign",
            expected_rule_id=None,
            events=events,
        )
    )

    # ---------------------------------------------------------
    # BENIGN SCENARIO 4: LOW-VOLUME HOST ACTIVITY
    # ---------------------------------------------------------

    events = [
        create_event(
            event_type="network_connection",
            occurred_at=base_time - timedelta(seconds=i),
            source_ip="192.0.2.73",
            destination_ip=f"198.51.100.{i + 70}",
            destination_port=443,
            protocol="tcp",
        )
        for i in range(3)
    ]

    scenarios.append(
        Scenario(
            scenario_id="BEN-004",
            name="Routine connections to a few hosts",
            category="benign",
            expected_rule_id=None,
            events=events,
        )
    )

    # ---------------------------------------------------------
    # BENIGN SCENARIO 5: LOW-VOLUME SERVICE ACTIVITY
    # ---------------------------------------------------------

    events = []

    for host_number in range(1, 3):
        for port in [80, 443]:
            events.append(
                create_event(
                    event_type="network_connection",
                    occurred_at=base_time - timedelta(
                        seconds=len(events)
                    ),
                    source_ip="192.0.2.74",
                    destination_ip=f"198.51.100.{host_number + 80}",
                    destination_port=port,
                    protocol="tcp",
                )
            )

    scenarios.append(
        Scenario(
            scenario_id="BEN-005",
            name="Small number of host and port combinations",
            category="benign",
            expected_rule_id=None,
            events=events,
        )
    )

    # ---------------------------------------------------------
    # BENIGN SCENARIO 6: IRREGULAR CONNECTION INTERVALS
    # ---------------------------------------------------------

    irregular_offsets = [-85, -80, -65, -60, -15, 0]

    events = [
        create_event(
            event_type="network_connection",
            occurred_at=base_time + timedelta(seconds=offset),
            source_ip="192.0.2.75",
            destination_ip="198.51.100.75",
            destination_port=443,
            protocol="tcp",
        )
        for offset in irregular_offsets
    ]

    scenarios.append(
        Scenario(
            scenario_id="BEN-006",
            name="Repeated connections with irregular intervals",
            category="benign",
            expected_rule_id=None,
            events=events,
        )
    )

    # ---------------------------------------------------------
    # BENIGN SCENARIO 7: LIMITED REMOTE ADMINISTRATION
    # ---------------------------------------------------------

    events = [
        create_event(
            event_type="network_connection",
            occurred_at=base_time - timedelta(seconds=10 * i),
            source_ip="192.0.2.76",
            destination_ip=f"198.51.100.{76 + i}",
            destination_port=3389 if i % 2 else 22,
            protocol="tcp",
        )
        for i in range(2)
    ]

    scenarios.append(
        Scenario(
            scenario_id="BEN-007",
            name="Routine remote administration to a small number of hosts",
            category="benign",
            expected_rule_id=None,
            events=events,
        )
    )

    return scenarios
