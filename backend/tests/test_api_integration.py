# --------------------------------------------------
# HEALTH AND EVENT INGESTION
# --------------------------------------------------

def test_health_endpoint(client):
    response = client.get("/api/v1/health")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "healthy"
    assert data["database"] == "connected"


def test_event_ingestion(client):
    payload = {
        "event_type": "authentication_failed",
        "source_ip": "198.51.100.251",
        "username": "integration-user",
        "outcome": "failure",
        "description": "Integration test authentication failure"
    }

    response = client.post(
        "/api/v1/events",
        json=payload
    )

    assert response.status_code == 201

    data = response.json()

    assert data["message"] == "Security event ingested"
    assert data["event_id"] is not None


def test_event_ingestion_rejects_invalid_port(client):
    payload = {
        "event_type": "network_connection",
        "destination_port": 70000
    }

    response = client.post(
        "/api/v1/events",
        json=payload
    )

    assert response.status_code == 422


def test_event_listing_rejects_invalid_limit(client):
    response = client.get(
        "/api/v1/events?limit=0"
    )

    assert response.status_code == 400


# --------------------------------------------------
# ALERT INVESTIGATION
# --------------------------------------------------

def test_get_alert(
    client,
    seeded_alert
):
    response = client.get(
        f"/api/v1/alerts/{seeded_alert}"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["alert"]["id"] == seeded_alert
    assert data["alert"]["title"] == "Integration Test Alert"


def test_missing_alert_returns_404(client):
    response = client.get(
        "/api/v1/alerts/999999"
    )

    assert response.status_code == 404


def test_alert_status_update(
    client,
    seeded_alert
):
    response = client.patch(
        f"/api/v1/alerts/{seeded_alert}/status",
        json={
            "status": "investigating"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert data["alert"]["status"] == "investigating"
    assert data["previous_status"] == "open"


def test_invalid_alert_status_returns_422(
    client,
    seeded_alert
):
    response = client.patch(
        f"/api/v1/alerts/{seeded_alert}/status",
        json={
            "status": "compromised"
        }
    )

    assert response.status_code == 422


def test_add_alert_investigation_note(
    client,
    seeded_alert
):
    response = client.post(
        f"/api/v1/alerts/{seeded_alert}/notes",
        json={
            "content": "Integration test investigation note"
        }
    )

    assert response.status_code == 201

    assert response.json()["note"]["content"] == (
        "Integration test investigation note"
    )


# --------------------------------------------------
# ALERT EVIDENCE
# --------------------------------------------------

def test_link_event_as_alert_evidence(
    client,
    seeded_alert,
    seeded_event
):
    response = client.post(
        f"/api/v1/alerts/{seeded_alert}/evidence",
        json={
            "event_id": seeded_event,
            "analyst_note": "Relevant test evidence"
        }
    )

    assert response.status_code == 201

    data = response.json()

    assert data["evidence"]["alert_id"] == seeded_alert
    assert data["evidence"]["event_id"] == seeded_event


def test_duplicate_evidence_link_returns_409(
    client,
    seeded_alert,
    seeded_event
):
    url = f"/api/v1/alerts/{seeded_alert}/evidence"

    payload = {
        "event_id": seeded_event,
        "analyst_note": "Duplicate test"
    }

    first_response = client.post(url, json=payload)

    second_response = client.post(url, json=payload)

    assert first_response.status_code == 201
    assert second_response.status_code == 409


def test_missing_event_evidence_returns_404(
    client,
    seeded_alert
):
    response = client.post(
        f"/api/v1/alerts/{seeded_alert}/evidence",
        json={
            "event_id": 999999
        }
    )

    assert response.status_code == 404


# --------------------------------------------------
# CORRELATION MANAGEMENT
# --------------------------------------------------

def test_list_correlations(client, seeded_correlation):
    response = client.get(
        "/api/v1/correlations"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["count"] == 1
    assert data["correlations"][0]["id"] == seeded_correlation


def test_get_correlation(
    client,
    seeded_correlation
):
    response = client.get(
        f"/api/v1/correlations/{seeded_correlation}"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["correlation"]["id"] == seeded_correlation
    assert data["alert_count"] == 1


def test_missing_correlation_returns_404(client):
    response = client.get(
        "/api/v1/correlations/999999"
    )

    assert response.status_code == 404


def test_update_correlation_status(
    client,
    seeded_correlation
):
    response = client.patch(
        f"/api/v1/correlations/{seeded_correlation}/status",
        json={
            "status": "investigating",
            "actor": "integration-analyst",
            "details": "Integration test status change"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert data["previous_status"] == "open"
    assert data["new_status"] == "investigating"


def test_invalid_correlation_status_returns_422(
    client,
    seeded_correlation
):
    response = client.patch(
        f"/api/v1/correlations/{seeded_correlation}/status",
        json={
            "status": "closed"
        }
    )

    assert response.status_code == 422


def test_assign_correlation_case(
    client,
    seeded_correlation
):
    response = client.patch(
        f"/api/v1/correlations/{seeded_correlation}/assignment",
        json={
            "assigned_to": "integration-analyst",
            "actor": "integration-analyst"
        }
    )

    assert response.status_code == 200

    assert response.json()["assigned_to"] == (
        "integration-analyst"
    )


def test_add_correlation_note(
    client,
    seeded_correlation
):
    response = client.post(
        f"/api/v1/correlations/{seeded_correlation}/notes",
        json={
            "author": "integration-analyst",
            "content": "Integration test correlation note"
        }
    )

    assert response.status_code == 200

    assert response.json()["note_id"] is not None


def test_whitespace_only_correlation_note_is_rejected(
    client,
    seeded_correlation
):
    response = client.post(
        f"/api/v1/correlations/{seeded_correlation}/notes",
        json={
            "author": "integration-analyst",
            "content": "     "
        }
    )

    assert response.status_code == 422


# --------------------------------------------------
# CASE TIMELINE AND AUDIT HISTORY
# --------------------------------------------------

def test_correlation_activity_is_recorded(
    client,
    seeded_correlation
):
    client.patch(
        f"/api/v1/correlations/{seeded_correlation}/status",
        json={
            "status": "investigating",
            "actor": "integration-analyst"
        }
    )

    client.patch(
        f"/api/v1/correlations/{seeded_correlation}/assignment",
        json={
            "assigned_to": "integration-analyst",
            "actor": "integration-analyst"
        }
    )

    client.post(
        f"/api/v1/correlations/{seeded_correlation}/notes",
        json={
            "author": "integration-analyst",
            "content": "Activity verification note"
        }
    )

    timeline_response = client.get(
        f"/api/v1/correlations/{seeded_correlation}/timeline"
    )

    audit_response = client.get(
        f"/api/v1/correlations/{seeded_correlation}/audit"
    )

    assert timeline_response.status_code == 200
    assert audit_response.status_code == 200

    timeline = timeline_response.json()["timeline"]
    audit = audit_response.json()["audit_history"]

    timeline_actions = {
        item["action"]
        for item in timeline
    }

    audit_actions = {
        item["action"]
        for item in audit
    }

    assert "status_changed" in timeline_actions
    assert "analyst_assigned" in timeline_actions
    assert "note_added" in timeline_actions

    assert "status_changed" in audit_actions
    assert "analyst_assigned" in audit_actions
    assert "note_added" in audit_actions
