from datetime import datetime, timedelta, timezone

from app.database import get_connection
from app.detection.correlation import correlate_alerts
from app.detection.engine import evaluate_event


def insert_event(
    connection,
    *,
    event_type,
    source_ip,
    username=None,
    outcome=None,
    occurred_at=None,
    received_at=None,
    destination_ip=None,
    destination_port=None,
    protocol=None,
):
    timestamp = datetime.now(timezone.utc)

    occurred_at = occurred_at or timestamp
    received_at = received_at or timestamp

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
            event_type,
            source_ip,
            username,
            outcome,
            "Automated detection test event",
            occurred_at.isoformat(),
            received_at.isoformat(),
            destination_ip,
            destination_port,
            protocol,
        ),
    )

    return {
        "event_type": event_type,
        "source_ip": source_ip,
        "username": username,
        "outcome": outcome,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "protocol": protocol,
    }


def insert_alert(
    connection,
    *,
    source_ip,
    detection_rule,
    severity="high",
    created_at=None,
    status="open",
):
    timestamp = created_at or datetime.now(timezone.utc)

    cursor = connection.execute(
        """
        INSERT INTO security_alerts (
            title,
            severity,
            description,
            source_ip,
            detection_rule,
            created_at,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "Detection Test Alert",
            severity,
            "Automated test alert",
            source_ip,
            detection_rule,
            timestamp.isoformat(),
            status,
        ),
    )

    return cursor.lastrowid


def get_alert_count(connection, detection_rule):
    row = connection.execute(
        """
        SELECT COUNT(*) AS total
        FROM security_alerts
        WHERE detection_rule = ?
        """,
        (detection_rule,),
    ).fetchone()

    return row["total"]


# ============================================================
# BEACONING DETECTION
# ============================================================

def test_beaconing_detects_six_regular_connections(
    isolated_database,
):
    source_ip = "203.0.113.80"
    destination_ip = "192.0.2.220"
    base_time = datetime.now(timezone.utc) - timedelta(minutes=2)

    with get_connection() as connection:
        results = []

        for interval in range(6):
            event = insert_event(
                connection,
                event_type="network_connection",
                source_ip=source_ip,
                occurred_at=base_time + timedelta(seconds=interval * 10),
                destination_ip=destination_ip,
                destination_port=8443,
                protocol="TCP",
            )

            detections = evaluate_event(connection, event)

            beaconing_results = [
                item
                for item in detections
                if item["rule_id"] == "AEGIS-NET-004"
            ]

            results.append(beaconing_results)

        assert all(not result for result in results[:5])

        assert len(results[5]) == 1

        detection = results[5][0]

        assert detection["created"] is True
        assert detection["connection_count"] == 6
        assert detection["average_interval_seconds"] == 10.0
        assert detection["interval_variation"] == 0.0
        assert detection["destination_ip"] == destination_ip
        assert detection["severity"] == "high"

        assert get_alert_count(
            connection,
            "AEGIS-NET-004",
        ) == 1


def test_beaconing_rejects_irregular_connection_intervals(
    isolated_database,
):
    source_ip = "203.0.113.81"
    destination_ip = "192.0.2.221"

    base_time = datetime.now(timezone.utc) - timedelta(minutes=3)

    offsets = [0, 12, 72, 80, 125, 135]

    with get_connection() as connection:
        detections = []

        for offset in offsets:
            event = insert_event(
                connection,
                event_type="network_connection",
                source_ip=source_ip,
                occurred_at=base_time + timedelta(seconds=offset),
                destination_ip=destination_ip,
                destination_port=8443,
                protocol="TCP",
            )

            detections.extend(evaluate_event(connection, event))

        beaconing_results = [
            item
            for item in detections
            if item["rule_id"] == "AEGIS-NET-004"
        ]

        assert beaconing_results == []

        assert get_alert_count(
            connection,
            "AEGIS-NET-004",
        ) == 0


def test_beaconing_reuses_existing_active_alert(
    isolated_database,
):
    source_ip = "203.0.113.82"
    destination_ip = "192.0.2.222"

    base_time = datetime.now(timezone.utc) - timedelta(minutes=2)

    with get_connection() as connection:
        for interval in range(6):
            event = insert_event(
                connection,
                event_type="network_connection",
                source_ip=source_ip,
                occurred_at=base_time + timedelta(seconds=interval * 10),
                destination_ip=destination_ip,
                destination_port=8443,
                protocol="TCP",
            )

            first_results = evaluate_event(connection, event)

        first_detection = next(
            item
            for item in first_results
            if item["rule_id"] == "AEGIS-NET-004"
        )

        assert first_detection["created"] is True

        next_event = insert_event(
            connection,
            event_type="network_connection",
            source_ip=source_ip,
            occurred_at=base_time + timedelta(seconds=60),
            destination_ip=destination_ip,
            destination_port=8443,
            protocol="TCP",
        )

        second_results = evaluate_event(connection, next_event)

        second_detection = next(
            item
            for item in second_results
            if item["rule_id"] == "AEGIS-NET-004"
        )

        assert second_detection["created"] is False
        assert second_detection["alert_id"] == first_detection["alert_id"]

        assert get_alert_count(
            connection,
            "AEGIS-NET-004",
        ) == 1


# ============================================================
# PASSWORD SPRAYING DETECTION
# ============================================================

def test_password_spraying_detects_five_distinct_accounts(
    isolated_database,
):
    source_ip = "203.0.113.90"

    usernames = [
        "alice",
        "bob",
        "charlie",
        "david",
        "emily",
    ]

    with get_connection() as connection:
        results = []

        for username in usernames:
            event = insert_event(
                connection,
                event_type="authentication",
                source_ip=source_ip,
                username=username,
                outcome="failure",
            )

            detections = evaluate_event(connection, event)

            spraying_results = [
                item
                for item in detections
                if item["rule_id"] == "AEGIS-AUTH-002"
            ]

            results.append(spraying_results)

        assert all(not result for result in results[:4])

        assert len(results[4]) == 1

        detection = results[4][0]

        assert detection["created"] is True
        assert detection["targeted_account_count"] == 5
        assert detection["severity"] == "high"

        assert get_alert_count(
            connection,
            "AEGIS-AUTH-002",
        ) == 1


def test_password_spraying_does_not_trigger_for_one_account(
    isolated_database,
):
    source_ip = "203.0.113.91"

    with get_connection() as connection:
        detections = []

        for _ in range(6):
            event = insert_event(
                connection,
                event_type="authentication",
                source_ip=source_ip,
                username="same-user",
                outcome="failure",
            )

            detections.extend(evaluate_event(connection, event))

        spraying_results = [
            item
            for item in detections
            if item["rule_id"] == "AEGIS-AUTH-002"
        ]

        assert spraying_results == []

        assert get_alert_count(
            connection,
            "AEGIS-AUTH-002",
        ) == 0


def test_password_spraying_reuses_existing_active_alert(
    isolated_database,
):
    source_ip = "203.0.113.92"

    with get_connection() as connection:
        for username in ["alice", "bob", "charlie", "david", "emily"]:
            event = insert_event(
                connection,
                event_type="authentication",
                source_ip=source_ip,
                username=username,
                outcome="failure",
            )

            results = evaluate_event(connection, event)

        first_detection = next(
            item
            for item in results
            if item["rule_id"] == "AEGIS-AUTH-002"
        )

        assert first_detection["created"] is True

        next_event = insert_event(
            connection,
            event_type="authentication",
            source_ip=source_ip,
            username="frank",
            outcome="failure",
        )

        next_results = evaluate_event(connection, next_event)

        second_detection = next(
            item
            for item in next_results
            if item["rule_id"] == "AEGIS-AUTH-002"
        )

        assert second_detection["created"] is False
        assert second_detection["alert_id"] == first_detection["alert_id"]
        assert second_detection["targeted_account_count"] == 6

        assert get_alert_count(
            connection,
            "AEGIS-AUTH-002",
        ) == 1


# ============================================================
# BRUTE FORCE DETECTION
# ============================================================

def test_brute_force_detects_five_failures_against_one_account(
    isolated_database,
):
    source_ip = "203.0.113.100"
    username = "target-user"

    with get_connection() as connection:
        results = []

        for _ in range(5):
            event = insert_event(
                connection,
                event_type="authentication",
                source_ip=source_ip,
                username=username,
                outcome="failure",
            )

            detections = evaluate_event(connection, event)

            brute_force_results = [
                item
                for item in detections
                if item["rule_id"] == "AEGIS-AUTH-001"
            ]

            results.append(brute_force_results)

        assert all(not result for result in results[:4])

        assert len(results[4]) == 1

        detection = results[4][0]

        assert detection["created"] is True
        assert detection["attempt_count"] == 5
        assert detection["severity"] == "high"

        assert get_alert_count(
            connection,
            "AEGIS-AUTH-001",
        ) == 1


def test_brute_force_ignores_successful_authentication(
    isolated_database,
):
    source_ip = "203.0.113.101"

    with get_connection() as connection:
        detections = []

        for _ in range(6):
            event = insert_event(
                connection,
                event_type="authentication",
                source_ip=source_ip,
                username="successful-user",
                outcome="success",
            )

            detections.extend(evaluate_event(connection, event))

        brute_force_results = [
            item
            for item in detections
            if item["rule_id"] == "AEGIS-AUTH-001"
        ]

        assert brute_force_results == []

        assert get_alert_count(
            connection,
            "AEGIS-AUTH-001",
        ) == 0


# ============================================================
# ALERT CORRELATION
# ============================================================

def test_correlation_created_for_two_distinct_detection_rules(
    isolated_database,
):
    source_ip = "198.51.100.240"
    now = datetime.now(timezone.utc)

    with get_connection() as connection:
        first_alert = insert_alert(
            connection,
            source_ip=source_ip,
            detection_rule="AEGIS-AUTH-001",
            severity="high",
            created_at=now - timedelta(minutes=2),
        )

        second_alert = insert_alert(
            connection,
            source_ip=source_ip,
            detection_rule="AEGIS-AUTH-002",
            severity="high",
            created_at=now,
        )

        result = correlate_alerts(connection, source_ip)

        assert result is not None
        assert result["created"] is True
        assert result["alert_count"] == 2
        assert result["severity"] == "high"

        linked_alerts = connection.execute(
            """
            SELECT alert_id
            FROM security_correlation_alerts
            WHERE correlation_id = ?
            """,
            (result["correlation_id"],),
        ).fetchall()

        linked_ids = {row["alert_id"] for row in linked_alerts}

        assert linked_ids == {first_alert, second_alert}


def test_correlation_not_created_for_same_detection_rule(
    isolated_database,
):
    source_ip = "198.51.100.241"
    now = datetime.now(timezone.utc)

    with get_connection() as connection:
        insert_alert(
            connection,
            source_ip=source_ip,
            detection_rule="AEGIS-AUTH-001",
            created_at=now - timedelta(minutes=1),
        )

        insert_alert(
            connection,
            source_ip=source_ip,
            detection_rule="AEGIS-AUTH-001",
            created_at=now,
        )

        result = correlate_alerts(connection, source_ip)

        assert result is None

        correlation_count = connection.execute(
            """
            SELECT COUNT(*) AS total
            FROM security_correlations
            """
        ).fetchone()["total"]

        assert correlation_count == 0


def test_correlation_updates_existing_open_case(
    isolated_database,
):
    source_ip = "198.51.100.242"
    now = datetime.now(timezone.utc)

    with get_connection() as connection:
        insert_alert(
            connection,
            source_ip=source_ip,
            detection_rule="AEGIS-AUTH-001",
            severity="medium",
            created_at=now - timedelta(minutes=2),
        )

        insert_alert(
            connection,
            source_ip=source_ip,
            detection_rule="AEGIS-AUTH-002",
            severity="high",
            created_at=now - timedelta(minutes=1),
        )

        first_result = correlate_alerts(connection, source_ip)

        assert first_result is not None
        assert first_result["created"] is True
        assert first_result["alert_count"] == 2

        insert_alert(
            connection,
            source_ip=source_ip,
            detection_rule="AEGIS-NET-001",
            severity="critical",
            created_at=now,
        )

        second_result = correlate_alerts(connection, source_ip)

        assert second_result is not None
        assert second_result["created"] is False
        assert (
            second_result["correlation_id"]
            == first_result["correlation_id"]
        )
        assert second_result["alert_count"] == 3
        assert second_result["severity"] == "critical"

        correlation_count = connection.execute(
            """
            SELECT COUNT(*) AS total
            FROM security_correlations
            """
        ).fetchone()["total"]

        assert correlation_count == 1


def test_correlation_returns_none_without_source_ip(
    isolated_database,
):
    with get_connection() as connection:
        result = correlate_alerts(connection, None)

        assert result is None

        correlation_count = connection.execute(
            """
            SELECT COUNT(*) AS total
            FROM security_correlations
            """
        ).fetchone()["total"]

        assert correlation_count == 0


# ============================================================
# NETWORK PORT SCAN DETECTION
# ============================================================

def test_port_scan_detects_ten_distinct_ports(isolated_database):
    source_ip = "203.0.113.110"
    destination_ip = "192.0.2.110"

    with get_connection() as connection:
        results = []

        for port in range(8000, 8010):
            event = insert_event(
                connection,
                event_type="network_connection",
                source_ip=source_ip,
                destination_ip=destination_ip,
                destination_port=port,
                protocol="TCP",
            )

            detections = evaluate_event(connection, event)

            results.append([
                item for item in detections
                if item["rule_id"] == "AEGIS-NET-001"
            ])

        assert all(not result for result in results[:9])
        assert len(results[9]) == 1

        detection = results[9][0]

        assert detection["created"] is True
        assert detection["distinct_port_count"] == 10
        assert detection["destination_ip"] == destination_ip
        assert detection["severity"] == "high"

        assert get_alert_count(connection, "AEGIS-NET-001") == 1


def test_port_scan_ignores_repeated_destination_ports(
    isolated_database,
):
    source_ip = "203.0.113.111"
    destination_ip = "192.0.2.111"

    with get_connection() as connection:
        detections = []

        for _ in range(15):
            event = insert_event(
                connection,
                event_type="network_connection",
                source_ip=source_ip,
                destination_ip=destination_ip,
                destination_port=8080,
                protocol="TCP",
            )

            detections.extend(evaluate_event(connection, event))

        port_scan_results = [
            item for item in detections
            if item["rule_id"] == "AEGIS-NET-001"
        ]

        assert port_scan_results == []
        assert get_alert_count(connection, "AEGIS-NET-001") == 0


def test_port_scan_reuses_existing_active_alert(isolated_database):
    source_ip = "203.0.113.112"
    destination_ip = "192.0.2.112"

    with get_connection() as connection:
        for port in range(9000, 9010):
            event = insert_event(
                connection,
                event_type="network_connection",
                source_ip=source_ip,
                destination_ip=destination_ip,
                destination_port=port,
                protocol="TCP",
            )

            results = evaluate_event(connection, event)

        first_detection = next(
            item for item in results
            if item["rule_id"] == "AEGIS-NET-001"
        )

        assert first_detection["created"] is True

        next_event = insert_event(
            connection,
            event_type="network_connection",
            source_ip=source_ip,
            destination_ip=destination_ip,
            destination_port=9010,
            protocol="TCP",
        )

        next_results = evaluate_event(connection, next_event)

        second_detection = next(
            item for item in next_results
            if item["rule_id"] == "AEGIS-NET-001"
        )

        assert second_detection["created"] is False
        assert second_detection["alert_id"] == first_detection["alert_id"]

        assert get_alert_count(connection, "AEGIS-NET-001") == 1


# ============================================================
# HORIZONTAL NETWORK SCAN DETECTION
# ============================================================

def test_horizontal_scan_detects_ten_distinct_destinations(
    isolated_database,
):
    source_ip = "203.0.113.120"
    destination_port = 443

    with get_connection() as connection:
        results = []

        for host in range(1, 11):
            destination_ip = f"192.0.2.{host}"

            event = insert_event(
                connection,
                event_type="network_connection",
                source_ip=source_ip,
                destination_ip=destination_ip,
                destination_port=destination_port,
                protocol="TCP",
            )

            detections = evaluate_event(connection, event)

            results.append([
                item for item in detections
                if item["rule_id"] == "AEGIS-NET-002"
            ])

        assert all(not result for result in results[:9])
        assert len(results[9]) == 1

        detection = results[9][0]

        assert detection["created"] is True
        assert detection["destination_count"] == 10
        assert detection["destination_port"] == destination_port
        assert detection["severity"] == "high"

        assert get_alert_count(connection, "AEGIS-NET-002") == 1


def test_horizontal_scan_ignores_repeated_destination_ips(
    isolated_database,
):
    source_ip = "203.0.113.121"

    with get_connection() as connection:
        detections = []

        for _ in range(15):
            event = insert_event(
                connection,
                event_type="network_connection",
                source_ip=source_ip,
                destination_ip="192.0.2.121",
                destination_port=443,
                protocol="TCP",
            )

            detections.extend(evaluate_event(connection, event))

        horizontal_results = [
            item for item in detections
            if item["rule_id"] == "AEGIS-NET-002"
        ]

        assert horizontal_results == []
        assert get_alert_count(connection, "AEGIS-NET-002") == 0


def test_horizontal_scan_reuses_existing_active_alert(
    isolated_database,
):
    source_ip = "203.0.113.122"
    destination_port = 443

    with get_connection() as connection:
        for host in range(1, 11):
            event = insert_event(
                connection,
                event_type="network_connection",
                source_ip=source_ip,
                destination_ip=f"192.0.2.{host}",
                destination_port=destination_port,
                protocol="TCP",
            )

            results = evaluate_event(connection, event)

        first_detection = next(
            item for item in results
            if item["rule_id"] == "AEGIS-NET-002"
        )

        assert first_detection["created"] is True

        next_event = insert_event(
            connection,
            event_type="network_connection",
            source_ip=source_ip,
            destination_ip="192.0.2.11",
            destination_port=destination_port,
            protocol="TCP",
        )

        next_results = evaluate_event(connection, next_event)

        second_detection = next(
            item for item in next_results
            if item["rule_id"] == "AEGIS-NET-002"
        )

        assert second_detection["created"] is False
        assert second_detection["alert_id"] == first_detection["alert_id"]

        assert get_alert_count(connection, "AEGIS-NET-002") == 1


# ============================================================
# NETWORK SERVICE SWEEP DETECTION
# ============================================================

def test_service_sweep_detects_twenty_distinct_ip_port_pairs(
    isolated_database,
):
    source_ip = "203.0.113.130"

    with get_connection() as connection:
        results = []

        for index in range(20):
            destination_ip = f"192.0.2.{index + 1}"
            destination_port = 8000 + index

            event = insert_event(
                connection,
                event_type="network_connection",
                source_ip=source_ip,
                destination_ip=destination_ip,
                destination_port=destination_port,
                protocol="TCP",
            )

            detections = evaluate_event(connection, event)

            results.append([
                item for item in detections
                if item["rule_id"] == "AEGIS-NET-003"
            ])

        assert all(not result for result in results[:19])
        assert len(results[19]) == 1

        detection = results[19][0]

        assert detection["created"] is True
        assert detection["destination_pair_count"] == 20
        assert detection["severity"] == "high"

        assert get_alert_count(connection, "AEGIS-NET-003") == 1


def test_service_sweep_ignores_duplicate_ip_port_pairs(
    isolated_database,
):
    source_ip = "203.0.113.131"

    with get_connection() as connection:
        detections = []

        for _ in range(25):
            event = insert_event(
                connection,
                event_type="network_connection",
                source_ip=source_ip,
                destination_ip="192.0.2.131",
                destination_port=8080,
                protocol="TCP",
            )

            detections.extend(evaluate_event(connection, event))

        sweep_results = [
            item for item in detections
            if item["rule_id"] == "AEGIS-NET-003"
        ]

        assert sweep_results == []
        assert get_alert_count(connection, "AEGIS-NET-003") == 0


def test_service_sweep_reuses_existing_active_alert(
    isolated_database,
):
    source_ip = "203.0.113.132"

    with get_connection() as connection:
        for index in range(20):
            event = insert_event(
                connection,
                event_type="network_connection",
                source_ip=source_ip,
                destination_ip=f"192.0.2.{index + 1}",
                destination_port=8000 + index,
                protocol="TCP",
            )

            results = evaluate_event(connection, event)

        first_detection = next(
            item for item in results
            if item["rule_id"] == "AEGIS-NET-003"
        )

        assert first_detection["created"] is True

        next_event = insert_event(
            connection,
            event_type="network_connection",
            source_ip=source_ip,
            destination_ip="192.0.2.21",
            destination_port=8020,
            protocol="TCP",
        )

        next_results = evaluate_event(connection, next_event)

        second_detection = next(
            item for item in next_results
            if item["rule_id"] == "AEGIS-NET-003"
        )

        assert second_detection["created"] is False
        assert second_detection["alert_id"] == first_detection["alert_id"]

        assert get_alert_count(connection, "AEGIS-NET-003") == 1


# ============================================================
# EDGE CASES: TIME-WINDOW BOUNDARIES
# ============================================================

def test_port_scan_excludes_events_outside_time_window(
    isolated_database,
):
    source_ip = "203.0.113.140"
    destination_ip = "192.0.2.140"
    now = datetime.now(timezone.utc)

    with get_connection() as connection:
        # One event is older than the two-minute detection window.
        insert_event(
            connection,
            event_type="network_connection",
            source_ip=source_ip,
            destination_ip=destination_ip,
            destination_port=7999,
            received_at=now - timedelta(minutes=3),
        )

        results = []

        for port in range(8000, 8009):
            event = insert_event(
                connection,
                event_type="network_connection",
                source_ip=source_ip,
                destination_ip=destination_ip,
                destination_port=port,
                received_at=now,
            )

            results.extend(evaluate_event(connection, event))

        port_results = [
            item for item in results
            if item["rule_id"] == "AEGIS-NET-001"
        ]

        assert port_results == []
        assert get_alert_count(connection, "AEGIS-NET-001") == 0


def test_horizontal_scan_excludes_events_outside_time_window(
    isolated_database,
):
    source_ip = "203.0.113.141"
    now = datetime.now(timezone.utc)

    with get_connection() as connection:
        insert_event(
            connection,
            event_type="network_connection",
            source_ip=source_ip,
            destination_ip="192.0.2.1",
            destination_port=443,
            received_at=now - timedelta(minutes=3),
        )

        results = []

        for host in range(2, 11):
            event = insert_event(
                connection,
                event_type="network_connection",
                source_ip=source_ip,
                destination_ip=f"192.0.2.{host}",
                destination_port=443,
                received_at=now,
            )

            results.extend(evaluate_event(connection, event))

        horizontal_results = [
            item for item in results
            if item["rule_id"] == "AEGIS-NET-002"
        ]

        assert horizontal_results == []
        assert get_alert_count(connection, "AEGIS-NET-002") == 0


def test_service_sweep_excludes_events_outside_time_window(
    isolated_database,
):
    source_ip = "203.0.113.142"
    now = datetime.now(timezone.utc)

    with get_connection() as connection:
        insert_event(
            connection,
            event_type="network_connection",
            source_ip=source_ip,
            destination_ip="192.0.2.1",
            destination_port=7999,
            received_at=now - timedelta(minutes=6),
        )

        results = []

        for index in range(19):
            event = insert_event(
                connection,
                event_type="network_connection",
                source_ip=source_ip,
                destination_ip=f"192.0.2.{index + 2}",
                destination_port=8000 + index,
                received_at=now,
            )

            results.extend(evaluate_event(connection, event))

        sweep_results = [
            item for item in results
            if item["rule_id"] == "AEGIS-NET-003"
        ]

        assert sweep_results == []
        assert get_alert_count(connection, "AEGIS-NET-003") == 0


def test_beaconing_uses_occurred_at_for_time_window(
    isolated_database,
):
    source_ip = "203.0.113.143"
    destination_ip = "192.0.2.143"
    now = datetime.now(timezone.utc)

    with get_connection() as connection:
        # This event was received recently but occurred too long ago.
        insert_event(
            connection,
            event_type="network_connection",
            source_ip=source_ip,
            destination_ip=destination_ip,
            destination_port=8443,
            occurred_at=now - timedelta(minutes=12),
            received_at=now,
        )

        results = []

        for interval in range(5):
            event = insert_event(
                connection,
                event_type="network_connection",
                source_ip=source_ip,
                destination_ip=destination_ip,
                destination_port=8443,
                occurred_at=now + timedelta(seconds=interval * 10),
                received_at=now,
            )

            results.extend(evaluate_event(connection, event))

        beaconing_results = [
            item for item in results
            if item["rule_id"] == "AEGIS-NET-004"
        ]

        assert beaconing_results == []
        assert get_alert_count(connection, "AEGIS-NET-004") == 0


# ============================================================
# EDGE CASES: INCOMPLETE NETWORK TELEMETRY
# ============================================================

def test_network_detectors_ignore_incomplete_telemetry(
    isolated_database,
):
    with get_connection() as connection:
        incomplete_events = [
            {
                "event_type": "network_connection",
                "source_ip": None,
                "destination_ip": "192.0.2.150",
                "destination_port": 443,
            },
            {
                "event_type": "network_connection",
                "source_ip": "203.0.113.150",
                "destination_ip": None,
                "destination_port": 443,
            },
            {
                "event_type": "network_connection",
                "source_ip": "203.0.113.151",
                "destination_ip": "192.0.2.151",
                "destination_port": None,
            },
        ]

        for event in incomplete_events:
            results = evaluate_event(connection, event)

            network_results = [
                item for item in results
                if item["rule_id"] in {
                    "AEGIS-NET-001",
                    "AEGIS-NET-002",
                    "AEGIS-NET-003",
                    "AEGIS-NET-004",
                }
            ]

            assert network_results == []

        for rule_id in (
            "AEGIS-NET-001",
            "AEGIS-NET-002",
            "AEGIS-NET-003",
            "AEGIS-NET-004",
        ):
            assert get_alert_count(connection, rule_id) == 0


# ============================================================
# EDGE CASES: SOURCE-IP ISOLATION
# ============================================================

def test_port_scan_does_not_combine_different_source_ips(
    isolated_database,
):
    destination_ip = "192.0.2.160"

    with get_connection() as connection:
        results = []

        for source_ip, ports in (
            ("203.0.113.160", range(8000, 8005)),
            ("203.0.113.161", range(8005, 8010)),
        ):
            for port in ports:
                event = insert_event(
                    connection,
                    event_type="network_connection",
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    destination_port=port,
                    protocol="TCP",
                )

                results.extend(evaluate_event(connection, event))

        port_results = [
            item for item in results
            if item["rule_id"] == "AEGIS-NET-001"
        ]

        assert port_results == []
        assert get_alert_count(connection, "AEGIS-NET-001") == 0


def test_horizontal_scan_does_not_combine_different_source_ips(
    isolated_database,
):
    with get_connection() as connection:
        results = []

        for source_ip, hosts in (
            ("203.0.113.162", range(1, 6)),
            ("203.0.113.163", range(6, 11)),
        ):
            for host in hosts:
                event = insert_event(
                    connection,
                    event_type="network_connection",
                    source_ip=source_ip,
                    destination_ip=f"192.0.2.{host}",
                    destination_port=443,
                    protocol="TCP",
                )

                results.extend(evaluate_event(connection, event))

        horizontal_results = [
            item for item in results
            if item["rule_id"] == "AEGIS-NET-002"
        ]

        assert horizontal_results == []
        assert get_alert_count(connection, "AEGIS-NET-002") == 0


def test_service_sweep_does_not_combine_different_source_ips(
    isolated_database,
):
    with get_connection() as connection:
        results = []

        for source_ip in ("203.0.113.164", "203.0.113.165"):
            for index in range(10):
                event = insert_event(
                    connection,
                    event_type="network_connection",
                    source_ip=source_ip,
                    destination_ip=f"192.0.2.{index + 1}",
                    destination_port=8000 + index,
                    protocol="TCP",
                )

                results.extend(evaluate_event(connection, event))

        sweep_results = [
            item for item in results
            if item["rule_id"] == "AEGIS-NET-003"
        ]

        assert sweep_results == []
        assert get_alert_count(connection, "AEGIS-NET-003") == 0

def test_correlation_updates_existing_investigating_case(
    isolated_database,
):
    source_ip = "198.51.100.243"
    now = datetime.now(timezone.utc)

    with get_connection() as connection:
        insert_alert(
            connection,
            source_ip=source_ip,
            detection_rule="AEGIS-AUTH-011",
            severity="medium",
            created_at=now - timedelta(minutes=2),
        )

        insert_alert(
            connection,
            source_ip=source_ip,
            detection_rule="AEGIS-AUTH-012",
            severity="high",
            created_at=now - timedelta(minutes=1),
        )

        first_result = correlate_alerts(connection, source_ip)

        assert first_result is not None
        assert first_result["created"] is True
        assert first_result["alert_count"] == 2

        correlation_id = first_result["correlation_id"]

        connection.execute(
            """
            UPDATE security_correlations
            SET status = 'investigating'
            WHERE id = ?
            """,
            (correlation_id,),
        )

        insert_alert(
            connection,
            source_ip=source_ip,
            detection_rule="AEGIS-NET-011",
            severity="critical",
            created_at=now,
        )

        second_result = correlate_alerts(connection, source_ip)

        assert second_result is not None
        assert second_result["created"] is False
        assert second_result["correlation_id"] == correlation_id
        assert second_result["alert_count"] == 3
        assert second_result["severity"] == "critical"

        case_count = connection.execute(
            """
            SELECT COUNT(*) AS total
            FROM security_correlations
            WHERE source_ip = ?
            """,
            (source_ip,),
        ).fetchone()["total"]

        assert case_count == 1

        case = connection.execute(
            """
            SELECT status, alert_count
            FROM security_correlations
            WHERE id = ?
            """,
            (correlation_id,),
        ).fetchone()

        assert case["status"] == "investigating"
        assert case["alert_count"] == 3
