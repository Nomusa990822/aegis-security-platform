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
