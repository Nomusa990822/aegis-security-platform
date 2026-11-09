"""
Strict API request-contract regression tests.
"""

import pytest


def test_event_ingestion_rejects_unknown_properties(client):
    response = client.post(
        "/api/v1/events",
        json={
            "event_type": "authentication_failed",
            "source_ip": "198.51.100.10",
            "actor": "attacker-controlled-identity",
        },
    )
    assert response.status_code == 422


def test_alert_status_rejects_unknown_properties(client, seeded_alert):
    response = client.patch(
        f"/api/v1/alerts/{seeded_alert}/status",
        json={"status": "investigating", "actor": "attacker-controlled-identity"},
    )
    assert response.status_code == 422


def test_alert_note_rejects_unknown_properties(client, seeded_alert):
    response = client.post(
        f"/api/v1/alerts/{seeded_alert}/notes",
        json={
            "content": "A valid investigation note",
            "author": "attacker-controlled-identity",
        },
    )
    assert response.status_code == 422


def test_response_preview_rejects_unknown_properties(client):
    response = client.post(
        "/api/v1/response/preview",
        json={
            "alert_id": 1,
            "action": "block_ip",
            "target": "198.51.100.10",
            "requested_by": "attacker-controlled-identity",
        },
    )
    assert response.status_code == 422


def test_intelligence_request_rejects_unknown_properties(client):
    response = client.post(
        "/api/v1/intelligence/ip",
        json={"ip_address": "8.8.8.8", "actor": "attacker-controlled-identity"},
    )
    assert response.status_code == 422


@pytest.mark.parametrize("ip_address", ["", " ", "not-an-ip", "192.0.2.1/24"])
def test_intelligence_request_rejects_invalid_ip_addresses(client, ip_address):
    response = client.post(
        "/api/v1/intelligence/ip",
        json={"ip_address": ip_address},
    )
    assert response.status_code == 422
