
import json
from datetime import datetime, timezone

from app.intelligence.models import (
    EnrichmentStatus,
    IPClassification,
    IPIntelligenceAssessment,
    ProviderResult,
    ProviderStatus,
)
from app.intelligence.repository import IntelligenceRepository


def build_assessment(ip_address="8.8.8.8", score=85):
    return IPIntelligenceAssessment(
        ip_address=ip_address,
        classification=IPClassification.PUBLIC,
        is_global=True,
        enrichment_status=EnrichmentStatus.COMPLETED,
        threat_score=score,
        confidence=0.9,
        reputation="malicious",
        categories=["brute_force", "port_scanning"],
        provider_results=[
            ProviderResult(
                provider="abuseipdb",
                status=ProviderStatus.SUCCESS,
                reputation="malicious",
                confidence=0.9,
                categories=["brute_force"],
                details={
                    "abuse_confidence_score": score,
                    "reports": 12,
                },
            ),
            ProviderResult(
                provider="secondary_provider",
                status=ProviderStatus.SUCCESS,
                confidence=0.9,
                categories=["port_scanning"],
                details={"source": "test"},
            ),
        ],
        assessed_at=datetime.now(timezone.utc),
    )


def test_assessment_and_provider_results_survive_database_round_trip(
    isolated_database,
    seeded_alert,
):
    repository = IntelligenceRepository()
    assessment = build_assessment()

    assessment_id = repository.save_assessment(
        assessment,
        alert_id=seeded_alert,
    )

    stored = repository.get_assessment(assessment_id)

    assert stored is not None
    assert stored["ip_address"] == "8.8.8.8"
    assert stored["classification"] == "public"
    assert stored["is_global"] == 1
    assert stored["enrichment_status"] == "completed"
    assert stored["threat_score"] == 85
    assert stored["confidence"] == 0.9
    assert stored["reputation"] == "malicious"

    assert stored["categories"] == [
        "brute_force",
        "port_scanning",
    ]

    assert stored["alert_id"] == seeded_alert

    assert len(stored["provider_results"]) == 2

    abuse_result = stored["provider_results"][0]

    assert abuse_result["provider"] == "abuseipdb"
    assert abuse_result["status"] == "success"
    assert abuse_result["confidence"] == 0.9
    assert abuse_result["categories"] == ["brute_force"]
    assert abuse_result["details"]["abuse_confidence_score"] == 85
    assert abuse_result["details"]["reports"] == 12


def test_assessment_can_be_retrieved_by_linked_alert(
    isolated_database,
    seeded_alert,
):
    repository = IntelligenceRepository()

    assessment_id = repository.save_assessment(
        build_assessment(),
        alert_id=seeded_alert,
    )

    retrieved_id = repository.get_assessment_by_alert_id(
        seeded_alert
    )

    assert retrieved_id == assessment_id


def test_missing_assessment_returns_none(isolated_database):
    repository = IntelligenceRepository()

    assert repository.get_assessment(999999) is None


def test_missing_alert_assessment_returns_none(
    isolated_database,
):
    repository = IntelligenceRepository()

    assert repository.get_assessment_by_alert_id(999999) is None


def test_assessment_history_is_returned_newest_first(
    isolated_database,
    seeded_alert,
):
    repository = IntelligenceRepository()

    first_id = repository.save_assessment(
        build_assessment(score=25),
        alert_id=seeded_alert,
    )

    second_id = repository.save_assessment(
        build_assessment(score=85),
        alert_id=seeded_alert,
    )

    history = repository.get_assessments_by_ip("8.8.8.8")

    assert len(history) == 2
    assert history[0]["id"] == second_id
    assert history[1]["id"] == first_id

    assert history[0]["threat_score"] == 85
    assert history[1]["threat_score"] == 25


def test_history_limit_is_bounded(isolated_database):
    repository = IntelligenceRepository()

    for score in range(10):
        repository.save_assessment(
            build_assessment(score=score),
        )

    assert len(
        repository.get_assessments_by_ip("8.8.8.8", limit=3)
    ) == 3

    assert len(
        repository.get_assessments_by_ip("8.8.8.8", limit=0)
    ) == 1

    assert len(
        repository.get_assessments_by_ip("8.8.8.8", limit=1000)
    ) == 10


def test_assessment_categories_are_stored_as_valid_json(
    isolated_database,
):
    repository = IntelligenceRepository()

    assessment_id = repository.save_assessment(
        build_assessment()
    )

    stored = repository.get_assessment(assessment_id)

    assert isinstance(stored["categories"], list)
    assert json.dumps(stored["categories"])
