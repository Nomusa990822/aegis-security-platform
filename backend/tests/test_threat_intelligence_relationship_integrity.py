
from app.database import get_connection
from app.intelligence.repository import IntelligenceRepository

from test_threat_intelligence_persistence import build_assessment


def test_deleting_assessment_cascades_to_provider_results(
    isolated_database,
):
    repository = IntelligenceRepository()

    assessment_id = repository.save_assessment(
        build_assessment()
    )

    with get_connection() as connection:
        provider_count_before = connection.execute(
            """
            SELECT COUNT(*)
            FROM ip_intelligence_provider_results
            WHERE assessment_id = ?
            """,
            (assessment_id,),
        ).fetchone()[0]

        assert provider_count_before == 2

        connection.execute(
            """
            DELETE FROM ip_intelligence_assessments
            WHERE id = ?
            """,
            (assessment_id,),
        )

        connection.commit()

        assessment_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM ip_intelligence_assessments
            WHERE id = ?
            """,
            (assessment_id,),
        ).fetchone()[0]

        provider_count_after = connection.execute(
            """
            SELECT COUNT(*)
            FROM ip_intelligence_provider_results
            WHERE assessment_id = ?
            """,
            (assessment_id,),
        ).fetchone()[0]

    assert assessment_count == 0
    assert provider_count_after == 0

    assert repository.get_assessment(assessment_id) is None


def test_deleting_alert_preserves_assessment_and_provider_results(
    isolated_database,
    seeded_alert,
):
    repository = IntelligenceRepository()

    assessment_id = repository.save_assessment(
        build_assessment(),
        alert_id=seeded_alert,
    )

    with get_connection() as connection:
        connection.execute(
            """
            DELETE FROM security_alerts
            WHERE id = ?
            """,
            (seeded_alert,),
        )

        connection.commit()

    stored = repository.get_assessment(assessment_id)

    assert stored is not None
    assert stored["alert_id"] is None
    assert stored["ip_address"] == "8.8.8.8"

    assert len(stored["provider_results"]) == 2

    assert {
        result["provider"]
        for result in stored["provider_results"]
    } == {
        "abuseipdb",
        "secondary_provider",
    }

    assert repository.get_assessment_by_alert_id(
        seeded_alert
    ) is None


def test_deleting_one_assessment_does_not_delete_other_ip_history(
    isolated_database,
):
    repository = IntelligenceRepository()

    first_id = repository.save_assessment(
        build_assessment(
            ip_address="8.8.8.8",
            score=85,
        )
    )

    second_id = repository.save_assessment(
        build_assessment(
            ip_address="1.1.1.1",
            score=25,
        )
    )

    with get_connection() as connection:
        connection.execute(
            """
            DELETE FROM ip_intelligence_assessments
            WHERE id = ?
            """,
            (first_id,),
        )

        connection.commit()

    assert repository.get_assessment(first_id) is None

    remaining = repository.get_assessments_by_ip("1.1.1.1")

    assert len(remaining) == 1
    assert remaining[0]["id"] == second_id
    assert remaining[0]["threat_score"] == 25

    assert len(
        repository.get_assessment(second_id)["provider_results"]
    ) == 2
