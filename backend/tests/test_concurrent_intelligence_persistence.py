from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from app.intelligence.repository import IntelligenceRepository

from test_threat_intelligence_persistence import build_assessment


def test_concurrent_assessments_persist_without_losing_provider_results(
    isolated_database,
    seeded_alert,
):
    repository = IntelligenceRepository()
    total_assessments = 24

    base_time = build_assessment().assessed_at

    assessments = [
        build_assessment(score=index).model_copy(
            update={
                "assessed_at": base_time + timedelta(seconds=index)
            }
        )
        for index in range(total_assessments)
    ]

    def save_assessment(assessment):
        return repository.save_assessment(
            assessment,
            alert_id=seeded_alert,
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        assessment_ids = list(
            executor.map(save_assessment, assessments)
        )

    assert len(assessment_ids) == total_assessments
    assert len(set(assessment_ids)) == total_assessments

    history = repository.get_assessments_by_ip(
        "8.8.8.8",
        limit=100,
    )

    assert len(history) == total_assessments

    expected_ids = {
        assessment_id: assessment
        for assessment_id, assessment in zip(
            assessment_ids,
            assessments,
        )
    }

    # Every assessment must retain its own provider results.
    for assessment_id in assessment_ids:
        stored = repository.get_assessment(assessment_id)

        assert stored is not None
        assert stored["alert_id"] == seeded_alert
        assert len(stored["provider_results"]) == 2

        assert {
            result["provider"]
            for result in stored["provider_results"]
        } == {
            "abuseipdb",
            "secondary_provider",
        }

        expected = expected_ids[assessment_id]

        assert stored["threat_score"] == expected.threat_score
        assert stored["categories"] == expected.categories

    # History must be newest first, including when writes were concurrent.
    expected_order = sorted(
        assessments,
        key=lambda assessment: assessment.assessed_at,
        reverse=True,
    )

    assert [
        item["threat_score"]
        for item in history
    ] == [
        assessment.threat_score
        for assessment in expected_order
    ]

    # The alert lookup must return the newest assessment.
    latest_id = repository.get_assessment_by_alert_id(
        seeded_alert
    )

    assert latest_id == history[0]["id"]


def test_concurrent_assessments_for_different_ips_remain_isolated(
    isolated_database,
):
    repository = IntelligenceRepository()

    assessments = [
        build_assessment(
            ip_address="8.8.8.8",
            score=85,
        ),
        build_assessment(
            ip_address="1.1.1.1",
            score=25,
        ),
        build_assessment(
            ip_address="9.9.9.9",
            score=65,
        ),
    ]

    with ThreadPoolExecutor(max_workers=3) as executor:
        assessment_ids = list(
            executor.map(
                repository.save_assessment,
                assessments,
            )
        )

    assert len(set(assessment_ids)) == 3

    expected = {
        assessment.ip_address: assessment.threat_score
        for assessment in assessments
    }

    for ip_address, score in expected.items():
        history = repository.get_assessments_by_ip(ip_address)

        assert len(history) == 1
        assert history[0]["ip_address"] == ip_address
        assert history[0]["threat_score"] == score

        stored = repository.get_assessment(history[0]["id"])

        assert stored is not None
        assert len(stored["provider_results"]) == 2
