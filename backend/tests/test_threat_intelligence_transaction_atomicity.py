from app.database import get_connection
from app.intelligence.repository import IntelligenceRepository

from test_threat_intelligence_persistence import build_assessment


class FailingConnectionProxy:
    """Intercept provider-result inserts while preserving real SQLite operations."""

    def __init__(self, connection):
        self.connection = connection

    def execute(self, sql, parameters=()):
        if "INSERT INTO ip_intelligence_provider_results" in sql:
            raise RuntimeError(
                "Simulated provider result failure"
            )

        return self.connection.execute(sql, parameters)


def test_provider_result_failure_rolls_back_entire_assessment(
    isolated_database,
):
    repository = IntelligenceRepository()
    assessment = build_assessment()

    connection = get_connection()

    try:
        proxy = FailingConnectionProxy(connection)

        try:
            repository.save_assessment(
                assessment,
                connection=proxy,
            )
        except RuntimeError as exc:
            assert "Simulated provider result failure" in str(exc)
        else:
            raise AssertionError(
                "Expected simulated database failure"
            )

        # The caller owns this transaction and must roll it back.
        connection.rollback()

        assessment_count = connection.execute(
            "SELECT COUNT(*) FROM ip_intelligence_assessments"
        ).fetchone()[0]

        provider_count = connection.execute(
            "SELECT COUNT(*) FROM ip_intelligence_provider_results"
        ).fetchone()[0]

        assert assessment_count == 0
        assert provider_count == 0

    finally:
        connection.close()


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
