
"""
AEGIS detection regression tests.

These tests verify that the core detection pipeline continues
to identify expected attack patterns and avoid known false
positive scenarios.

All tests use the isolated SQLite database provided by conftest.py.
"""

from app import database
from app.detection.registry import get_detection_rules


TEST_SOURCE_IP = "198.51.100.77"
TEST_DESTINATION_IP = "203.0.113.25"


def ingest_event(
    client,
    *,
    event_type,
    source_ip=TEST_SOURCE_IP,
    username=None,
    outcome=None,
    destination_ip=None,
    destination_port=None,
    protocol=None,
):
    """Submit one event through the public ingestion API."""

    return client.post(
        "/api/v1/events",
        json={
            "event_type": event_type,
            "source_ip": source_ip,
            "username": username,
            "outcome": outcome,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "protocol": protocol,
            "description": "Automated detection regression test",
        },
    )


def get_alert_count():
    """Return the number of alerts in the isolated test database."""

    with database.get_connection() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS total FROM security_alerts"
        ).fetchone()

    return row["total"]


def test_all_eight_detection_rules_are_registered():
    rules = get_detection_rules()

    registered_ids = {
        rule["rule_id"]
        for rule in rules
    }

    assert len(rules) == 8

    assert registered_ids == {
        "AEGIS-AUTH-001",
        "AEGIS-AUTH-002",
        "AEGIS-NET-001",
        "AEGIS-NET-002",
        "AEGIS-NET-003",
        "AEGIS-NET-004",
        "AEGIS-AUTH-003",
        "AEGIS-AUTH-004",
    }

    assert all(rule["enabled"] for rule in rules)


def test_brute_force_detected_after_threshold(client):
    responses = []

    for attempt in range(5):
        response = ingest_event(
            client,
            event_type="authentication",
            username="regression-user",
            outcome="failure",
        )

        assert response.status_code == 201
        responses.append(response.json())

    assert all(
        item["detection_count"] == 0
        for item in responses[:4]
    )

    final_result = responses[4]

    assert final_result["detection_count"] >= 1

    detected_rule_ids = {
        detection["rule_id"]
        for detection in final_result["detections"]
    }

    assert "AEGIS-AUTH-001" in detected_rule_ids

    brute_force_detection = next(
        detection
        for detection in final_result["detections"]
        if detection["rule_id"] == "AEGIS-AUTH-001"
    )

    assert brute_force_detection["created"] is True
    assert brute_force_detection["attempt_count"] >= 5
    assert get_alert_count() == 1


def test_brute_force_reuses_existing_active_alert(client):
    for _ in range(5):
        response = ingest_event(
            client,
            event_type="authentication",
            username="duplicate-test-user",
            outcome="failure",
        )

        assert response.status_code == 201

    assert get_alert_count() == 1

    repeated_response = ingest_event(
        client,
        event_type="authentication",
        username="duplicate-test-user",
        outcome="failure",
    )

    assert repeated_response.status_code == 201

    detections = repeated_response.json()["detections"]

    brute_force_detection = next(
        detection
        for detection in detections
        if detection["rule_id"] == "AEGIS-AUTH-001"
    )

    assert brute_force_detection["created"] is False
    assert brute_force_detection["message"] == (
        "Existing active alert matched"
    )

    assert get_alert_count() == 1


def test_successful_authentication_does_not_trigger_brute_force(client):
    for _ in range(8):
        response = ingest_event(
            client,
            event_type="authentication",
            username="legitimate-user",
            outcome="success",
        )

        assert response.status_code == 201
        assert response.json()["detection_count"] == 0

    assert get_alert_count() == 0


def test_password_spraying_detected_across_distinct_accounts(client):
    responses = []

    for account_number in range(5):
        response = ingest_event(
            client,
            event_type="authentication",
            username=f"spray-user-{account_number}",
            outcome="failure",
        )

        assert response.status_code == 201
        responses.append(response.json())

    assert all(
        item["detection_count"] == 0
        for item in responses[:4]
    )

    final_result = responses[4]

    detected_rule_ids = {
        detection["rule_id"]
        for detection in final_result["detections"]
    }

    assert "AEGIS-AUTH-002" in detected_rule_ids

    spraying_detection = next(
        detection
        for detection in final_result["detections"]
        if detection["rule_id"] == "AEGIS-AUTH-002"
    )

    assert spraying_detection["created"] is True
    assert spraying_detection["targeted_account_count"] >= 5
    assert get_alert_count() == 1


def test_port_scan_detected_across_distinct_ports(client):
    responses = []

    for port in range(20, 30):
        response = ingest_event(
            client,
            event_type="network_connection",
            destination_ip=TEST_DESTINATION_IP,
            destination_port=port,
            protocol="tcp",
        )

        assert response.status_code == 201
        responses.append(response.json())

    assert all(
        item["detection_count"] == 0
        for item in responses[:9]
    )

    final_result = responses[9]

    detected_rule_ids = {
        detection["rule_id"]
        for detection in final_result["detections"]
    }

    assert "AEGIS-NET-001" in detected_rule_ids

    port_scan_detection = next(
        detection
        for detection in final_result["detections"]
        if detection["rule_id"] == "AEGIS-NET-001"
    )

    assert port_scan_detection["created"] is True
    assert port_scan_detection["distinct_port_count"] >= 10
    assert get_alert_count() >= 1


def test_incomplete_network_event_does_not_trigger_port_scan(client):
    response = ingest_event(
        client,
        event_type="network_connection",
        destination_ip=TEST_DESTINATION_IP,
        destination_port=None,
    )

    assert response.status_code == 201
    assert response.json()["detection_count"] == 0
    assert get_alert_count() == 0


def test_detection_rules_endpoint_matches_registry(client):
    response = client.get("/api/v1/detection/rules")

    assert response.status_code == 200

    payload = response.json()

    assert payload["count"] == 8

    endpoint_rule_ids = {
        rule["rule_id"]
        for rule in payload["rules"]
    }

    registry_rule_ids = {
        rule["rule_id"]
        for rule in get_detection_rules()
    }

    assert endpoint_rule_ids == registry_rule_ids
