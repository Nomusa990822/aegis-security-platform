
"""
AEGIS adversarial input regression tests.

Verifies event-ingestion validation, malformed input rejection,
field boundaries, IP address validation and data integrity.
"""

import pytest

from app import database


def valid_event_payload():
    return {
        "event_type": "authentication",
        "source_ip": "8.8.8.8",
        "username": "security-test-user",
        "outcome": "failure",
        "destination_ip": "1.1.1.1",
        "destination_port": 443,
        "protocol": "TCP",
        "description": "Adversarial input test",
    }


def get_event_count():
    with database.get_connection() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS total FROM security_events"
        ).fetchone()

    return row["total"]


def test_valid_event_is_accepted_and_normalised(client):
    payload = valid_event_payload()
    payload["event_type"] = "  AUTHENTICATION  "
    payload["outcome"] = " FAILURE "
    payload["protocol"] = " TCP "

    response = client.post(
        "/api/v1/events",
        json=payload,
    )

    assert response.status_code == 201

    stored_response = client.get("/api/v1/events")

    assert stored_response.status_code == 200

    stored_event = stored_response.json()["events"][0]

    assert stored_event["event_type"] == "authentication"
    assert stored_event["outcome"] == "failure"
    assert stored_event["protocol"] == "tcp"


def test_valid_ipv6_addresses_are_accepted(client):
    payload = valid_event_payload()
    payload["source_ip"] = "2001:4860:4860::8888"
    payload["destination_ip"] = "2606:4700:4700::1111"

    response = client.post(
        "/api/v1/events",
        json=payload,
    )

    assert response.status_code == 201


@pytest.mark.parametrize(
    "event_type",
    [
        "",
        " ",
        "     ",
    ],
)
def test_blank_event_type_is_rejected(client, event_type):
    payload = valid_event_payload()
    payload["event_type"] = event_type

    response = client.post(
        "/api/v1/events",
        json=payload,
    )

    assert response.status_code == 422
    assert get_event_count() == 0


@pytest.mark.parametrize(
    "ip_address",
    [
        "not-an-ip",
        "999.999.999.999",
        "192.168.1",
        "192.168.1.1/24",
        "",
        " ",
    ],
)
def test_invalid_source_ip_is_rejected(client, ip_address):
    payload = valid_event_payload()
    payload["source_ip"] = ip_address

    response = client.post(
        "/api/v1/events",
        json=payload,
    )

    assert response.status_code == 422
    assert get_event_count() == 0


@pytest.mark.parametrize(
    "ip_address",
    [
        "invalid-destination",
        "300.1.1.1",
        "10.0.0.1/8",
        "",
    ],
)
def test_invalid_destination_ip_is_rejected(client, ip_address):
    payload = valid_event_payload()
    payload["destination_ip"] = ip_address

    response = client.post(
        "/api/v1/events",
        json=payload,
    )

    assert response.status_code == 422
    assert get_event_count() == 0


@pytest.mark.parametrize(
    "port",
    [
        0,
        -1,
        65536,
        100000,
    ],
)
def test_out_of_range_destination_port_is_rejected(client, port):
    payload = valid_event_payload()
    payload["destination_port"] = port

    response = client.post(
        "/api/v1/events",
        json=payload,
    )

    assert response.status_code == 422
    assert get_event_count() == 0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("event_type", "a" * 101),
        ("username", "u" * 257),
        ("outcome", "o" * 51),
        ("protocol", "p" * 21),
        ("description", "d" * 2001),
        ("source_ip", "1" * 46),
        ("destination_ip", "1" * 46),
    ],
)
def test_oversized_fields_are_rejected(client, field, value):
    payload = valid_event_payload()
    payload[field] = value

    response = client.post(
        "/api/v1/events",
        json=payload,
    )

    assert response.status_code == 422
    assert get_event_count() == 0


@pytest.mark.parametrize(
    "field",
    [
        "source_ip",
        "destination_ip",
        "username",
        "outcome",
        "protocol",
    ],
)
def test_optional_fields_can_be_omitted(client, field):
    payload = valid_event_payload()
    payload[field] = None

    response = client.post(
        "/api/v1/events",
        json=payload,
    )

    assert response.status_code == 201


def test_malformed_json_is_rejected(client):
    response = client.post(
        "/api/v1/events",
        content='{"event_type": ',
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 422
    assert get_event_count() == 0


def test_non_integer_destination_port_is_rejected(client):
    payload = valid_event_payload()
    payload["destination_port"] = "not-a-port"

    response = client.post(
        "/api/v1/events",
        json=payload,
    )

    assert response.status_code == 422
    assert get_event_count() == 0
