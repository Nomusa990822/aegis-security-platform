
import json
from datetime import datetime, timezone

from app.database import get_connection
from app.intelligence.models import IPIntelligenceAssessment


class IntelligenceRepository:
    """
    Persists IP intelligence assessments and provider results.

    Database connections are managed by this repository when one
    is not explicitly supplied by the caller.
    """

    def save_assessment(
        self,
        assessment: IPIntelligenceAssessment,
        alert_id: int | None = None,
        connection=None,
    ) -> int:
        """
        Save an assessment and its provider results.

        Returns the newly created assessment ID.
        """
        owns_connection = connection is None

        if owns_connection:
            connection = get_connection()

        try:
            assessed_at = assessment.assessed_at.isoformat()
            created_at = datetime.now(timezone.utc).isoformat()

            cursor = connection.execute(
                """
                INSERT INTO ip_intelligence_assessments (
                    ip_address,
                    classification,
                    is_global,
                    enrichment_status,
                    threat_score,
                    confidence,
                    reputation,
                    categories,
                    first_seen,
                    last_seen,
                    assessed_at,
                    created_at,
                    alert_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    assessment.ip_address,
                    assessment.classification.value,
                    int(assessment.is_global),
                    assessment.enrichment_status.value,
                    assessment.threat_score,
                    assessment.confidence,
                    assessment.reputation,
                    json.dumps(assessment.categories),
                    (
                        assessment.first_seen.isoformat()
                        if assessment.first_seen
                        else None
                    ),
                    (
                        assessment.last_seen.isoformat()
                        if assessment.last_seen
                        else None
                    ),
                    assessed_at,
                    created_at,
                    alert_id,
                ),
            )

            assessment_id = cursor.lastrowid

            for result in assessment.provider_results:
                connection.execute(
                    """
                    INSERT INTO ip_intelligence_provider_results (
                        assessment_id,
                        provider,
                        status,
                        reputation,
                        confidence,
                        categories,
                        details,
                        error,
                        checked_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        assessment_id,
                        result.provider,
                        (
                            result.status.value
                            if hasattr(result.status, "value")
                            else result.status
                        ),
                        result.reputation,
                        result.confidence,
                        json.dumps(result.categories),
                        json.dumps(result.details),
                        result.error,
                        result.checked_at.isoformat(),
                    ),
                )

            if owns_connection:
                connection.commit()

            return assessment_id

        except Exception:
            if owns_connection:
                connection.rollback()
            raise

        finally:
            if owns_connection:
                connection.close()

    def get_assessment(
        self,
        assessment_id: int,
        connection=None,
    ) -> dict | None:
        """
        Retrieve one assessment and its provider results.
        """
        owns_connection = connection is None

        if owns_connection:
            connection = get_connection()

        try:
            assessment = connection.execute(
                """
                SELECT *
                FROM ip_intelligence_assessments
                WHERE id = ?
                """,
                (assessment_id,),
            ).fetchone()

            if assessment is None:
                return None

            provider_results = connection.execute(
                """
                SELECT *
                FROM ip_intelligence_provider_results
                WHERE assessment_id = ?
                ORDER BY id ASC
                """,
                (assessment_id,),
            ).fetchall()

            result = dict(assessment)
            result["categories"] = json.loads(
                result["categories"]
            )
            result["provider_results"] = []

            for provider_result in provider_results:
                item = dict(provider_result)
                item["categories"] = json.loads(
                    item["categories"]
                )
                item["details"] = json.loads(
                    item["details"]
                )
                result["provider_results"].append(item)

            return result

        finally:
            if owns_connection:
                connection.close()

    def get_assessments_by_ip(
        self,
        ip_address: str,
        limit: int = 20,
        connection=None,
    ) -> list[dict]:
        """
        Retrieve assessment history for an IP address.

        Results are returned newest first.
        """
        owns_connection = connection is None

        if owns_connection:
            connection = get_connection()

        try:
            rows = connection.execute(
                """
                SELECT *
                FROM ip_intelligence_assessments
                WHERE ip_address = ?
                ORDER BY assessed_at DESC, id DESC
                LIMIT ?
                """,
                (ip_address, max(1, min(limit, 100))),
            ).fetchall()

            assessments = []

            for row in rows:
                item = dict(row)
                item["categories"] = json.loads(
                    item["categories"]
                )
                assessments.append(item)

            return assessments

        finally:
            if owns_connection:
                connection.close()
