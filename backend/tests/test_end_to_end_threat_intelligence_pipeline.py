from datetime import datetime, timezone

from app import main as main_module
from app.database import get_connection
from app.intelligence.models import (
    EnrichmentStatus,
    IPClassification,
    IPIntelligenceAssessment,
    ProviderResult,
    ProviderStatus,
)
from app.intelligence.repository import IntelligenceRepository


SOURCE_IP = "8.8.8.8"
SOURCE_SYSTEM = "step-37-integration"


class StubEnrichmentService:
    """Deterministic provider substitute for an end-to-end API test."""

    def __init__(self):
        self.calls = []

    async def enrich_ip(self, ip_address):
        self.calls.append(ip_address)

        return IPIntelligenceAssessment(
            ip_address=ip_address,
            classification=IPClassification.PUBLIC,
            is_global=True,
            enrichment_status=EnrichmentStatus.COMPLETED,
            threat_score=85,
            confidence=0.9,
            reputation="malicious",
            categories=["brute_force"],
            provider_results=[
                ProviderResult(
                    provider="abuseipdb",
                    status=ProviderStatus.SUCCESS,
                    reputation="malicious",
                    confidence=0.9,
                    categories=["brute_force"],
                    details={"abuse_confidence_score": 85},
                ),
                ProviderResult(
                    provider="secondary_provider",
                    status=ProviderStatus.SUCCESS,
                    confidence=0.8,
                    categories=["credential_attack"],
                    details={"source": "integration-test"},
                ),
            ],
            assessed_at=datetime.now(timezone.utc),
        )


def authentication_payload(index):
    return {
        "source_system": SOURCE_SYSTEM,
        "external_event_id": f"authentication-{index}",
        "event_type": "authentication",
        "source_ip": SOURCE_IP,
        "username": "administrator",
        "outcome": "failure",
        "description": "End-to-end brute-force integration test",
    }


def submit_brute_force_sequence(client):
    responses = []

    for index in range(5):
        response = client.post(
            "/api/v1/events",
            json=authentication_payload(index),
        )

        assert response.status_code == 201
        responses.append(response.json())

    return responses


def test_detected_alert_is_enriched_and_persisted_end_to_end(
    client,
    isolated_database,
    monkeypatch,
):
    service = StubEnrichmentService()

    monkeypatch.setattr(
        main_module.alert_intelligence_service,
        "enrichment_service",
        service,
    )

    responses = submit_brute_force_sequence(client)

    # The first four events must not trigger the threshold.
    assert all(
        result["detection_count"] == 0
        for result in responses[:4]
    )

    # The fifth event must trigger brute-force detection.
    final_result = responses[4]

    assert final_result["detection_count"] == 1
    assert final_result["detection"]["rule_id"] == "AEGIS-AUTH-001"

    alert_id = final_result["detection"]["alert_id"]
    assert alert_id is not None

    # Automatic enrichment must run once for the detected alert.
    assert service.calls == [SOURCE_IP]

    assert len(final_result["intelligence_enrichments"]) == 1

    enrichment = final_result["intelligence_enrichments"][0]

    assert enrichment["alert_id"] == alert_id
    assert enrichment["status"] == "completed"
    assert enrichment["threat_score"] == 85
    assert enrichment["reputation"] == "malicious"

    # Verify the alert exists in the production alert table.
    with get_connection() as connection:
        alert = connection.execute(
            """
            SELECT id, source_ip, detection_rule
            FROM security_alerts
            WHERE id = ?
            """,
            (alert_id,),
        ).fetchone()

        event_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM security_events
            WHERE source_system = ?
            """,
            (SOURCE_SYSTEM,),
        ).fetchone()[0]

    assert alert is not None
    assert alert["source_ip"] == SOURCE_IP
    assert alert["detection_rule"] == "AEGIS-AUTH-001"
    assert event_count == 5

    # Verify the assessment is linked to the alert and fully persisted.
    repository = IntelligenceRepository()

    assessment_id = repository.get_assessment_by_alert_id(alert_id)

    assert assessment_id is not None

    assessment = repository.get_assessment(assessment_id)

    assert assessment is not None
    assert assessment["alert_id"] == alert_id
    assert assessment["ip_address"] == SOURCE_IP
    assert assessment["enrichment_status"] == "completed"
    assert assessment["threat_score"] == 85
    assert assessment["reputation"] == "malicious"

    assert len(assessment["provider_results"]) == 2

    assert {
        result["provider"]
        for result in assessment["provider_results"]
    } == {
        "abuseipdb",
        "secondary_provider",
    }


def test_duplicate_event_does_not_repeat_detection_or_enrichment(
    client,
    isolated_database,
    monkeypatch,
):
    service = StubEnrichmentService()

    monkeypatch.setattr(
        main_module.alert_intelligence_service,
        "enrichment_service",
        service,
    )

    responses = submit_brute_force_sequence(client)

    original_result = responses[4]
    original_event_id = original_result["event_id"]
    alert_id = original_result["detection"]["alert_id"]

    assert len(service.calls) == 1

    # Replay the exact fifth event with the same source and external ID.
    duplicate_response = client.post(
        "/api/v1/events",
        json=authentication_payload(4),
    )

    assert duplicate_response.status_code == 200

    duplicate_result = duplicate_response.json()

    assert duplicate_result["duplicate"] is True
    assert duplicate_result["event_id"] == original_event_id
    assert duplicate_result["detection_count"] == 0
    assert duplicate_result["intelligence_enrichments"] == []

    # The replay must not call enrichment again.
    assert service.calls == [SOURCE_IP]

    repository = IntelligenceRepository()

    # There must still be exactly one assessment for this alert.
    assert repository.get_assessment_by_alert_id(alert_id) is not None

    history = repository.get_assessments_by_ip(SOURCE_IP)

    assert len(history) == 1

    with get_connection() as connection:
        event_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM security_events
            WHERE source_system = ?
            """,
            (SOURCE_SYSTEM,),
        ).fetchone()[0]

        alert_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM security_alerts
            WHERE id = ?
            """,
            (alert_id,),
        ).fetchone()[0]

    assert event_count == 5
    assert alert_count == 1