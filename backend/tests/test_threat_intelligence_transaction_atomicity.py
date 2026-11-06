
from app.intelligence.repository import IntelligenceRepository

from test_threat_intelligence_persistence import build_assessment


def test_provider_result_failure_rolls_back_entire_assessment(
    isolated_database,
):
    repository = IntelligenceRepository()
    assessment = build_assessment()

    with repository_connection() as connection:
        original_execute = connection.execute

        def failing_execute(sql, parameters=()):
            if "INSERT INTO ip_intelligence_provider_results" in sql:
                raise RuntimeError("Simulated provider result failure")

            return original_execute(sql, parameters)

        connection.execute = failing_execute

        try:
            try:
                repository.save_assessment(
                    assessment,
                    connection=connection,
                )
            except RuntimeError as exc:
                assert "Simulated provider result failure" in str(exc)
            else:
                raise AssertionError("Expected simulated database failure")

            connection.rollback()
        finally:
            connection.close()

    with repository_connection() as connection:
        assessment_count = connection.execute(
            "SELECT COUNT(*) FROM ip_intelligence_assessments"
        ).fetchone()[0]

        provider_count = connection.execute(
            "SELECT COUNT(*) FROM ip_intelligence_provider_results"
        ).fetchone()[0]

    assert assessment_count == 0
    assert provider_count == 0


def test_successful_assessment_persists_all_provider_results(
    isolated_database,
):
    repository = IntelligenceRepository()

    assessment_id = repository.save_assessment(
        build_assessment()
    )

    stored = repository.get_assessment(assessment_id)

    assert stored is not None
    assert len(stored["provider_results"]) == 2


def repository_connection():
    from app.database import get_connection

    return get_connection()
