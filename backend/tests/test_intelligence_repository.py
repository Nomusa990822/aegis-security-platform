
import pytest

from app.database import get_connection, initialize_database
from app.intelligence.models import (
    EnrichmentStatus,
    IPClassification,
    IPIntelligenceAssessment,
    ProviderResult,
    ProviderStatus,
)
from app.intelligence.repository import IntelligenceRepository


@pytest.fixture
def repository():
    initialize_database()
    return IntelligenceRepository()


def create_assessment(
    ip_address="8.8.8.8",
    provider_results=None,
):
    return IPIntelligenceAssessment(
        ip_address=ip_address,
        classification=IPClassification.PUBLIC,
        is_global=True,
        enrichment_status=EnrichmentStatus.COMPLETED,
        threat_score=85,
        confidence=0.90,
        reputation="malicious",
        categories=["brute_force", "botnet"],
        provider_results=provider_results or [],
    )


def test_save_and_retrieve_assessment(repository):
    assessment = create_assessment()

    assessment_id = repository.save_assessment(assessment)

    stored = repository.get_assessment(assessment_id)

    assert stored is not None
    assert stored["ip_address"] == "8.8.8.8"
    assert stored["classification"] == "public"
    assert stored["is_global"] == 1
    assert stored["threat_score"] == 85
    assert stored["confidence"] == 0.90
    assert stored["reputation"] == "malicious"
    assert stored["categories"] == ["brute_force", "botnet"]


def test_save_and_retrieve_provider_results(repository):
    provider_result = ProviderResult(
        provider="abuseipdb",
        status=ProviderStatus.SUCCESS,
        reputation="malicious",
        confidence=0.90,
        categories=["brute_force"],
        details={
            "abuse_confidence_score": 90,
            "total_reports": 25,
        },
    )

    assessment = create_assessment(
        provider_results=[provider_result]
    )

    assessment_id = repository.save_assessment(assessment)

    stored = repository.get_assessment(assessment_id)

    assert len(stored["provider_results"]) == 1

    result = stored["provider_results"][0]

    assert result["provider"] == "abuseipdb"
    assert result["status"] == "success"
    assert result["reputation"] == "malicious"
    assert result["confidence"] == 0.90
    assert result["categories"] == ["brute_force"]
    assert result["details"]["abuse_confidence_score"] == 90


def test_retrieve_nonexistent_assessment(repository):
    assert repository.get_assessment(-1) is None


def test_retrieve_assessment_history_by_ip(repository):
    first = create_assessment()
    second = create_assessment()

    repository.save_assessment(first)
    repository.save_assessment(second)

    history = repository.get_assessments_by_ip("8.8.8.8")

    assert len(history) >= 2
    assert all(item["ip_address"] == "8.8.8.8" for item in history)


def test_assessment_can_be_linked_to_alert(repository):
    connection = get_connection()

    try:
        alert_id = connection.execute(
            "SELECT id FROM security_alerts ORDER BY id LIMIT 1"
        ).fetchone()

        if alert_id is None:
            pytest.skip("No security alert exists in the test database")

        assessment_id = repository.save_assessment(
            create_assessment(),
            alert_id=alert_id["id"],
        )

        stored = repository.get_assessment(assessment_id)

        assert stored["alert_id"] == alert_id["id"]

    finally:
        connection.close()


def test_save_assessment_with_external_connection(repository):
    connection = get_connection()

    try:
        assessment_id = repository.save_assessment(
            create_assessment(),
            connection=connection,
        )

        stored = repository.get_assessment(
            assessment_id,
            connection=connection,
        )

        assert stored is not None
        assert stored["ip_address"] == "8.8.8.8"

        connection.rollback()

        rolled_back = connection.execute(
            """
            SELECT id
            FROM ip_intelligence_assessments
            WHERE id = ?
            """,
            (assessment_id,),
        ).fetchone()

        assert rolled_back is None

    finally:
        connection.close()
