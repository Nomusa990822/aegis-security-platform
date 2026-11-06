import asyncio
from datetime import datetime, timezone

from app.database import get_connection
from app.intelligence.alert_enrichment import AlertIntelligenceService
from app.intelligence.models import (
    EnrichmentStatus,
    IPClassification,
    IPIntelligenceAssessment,
)
from app.intelligence.repository import IntelligenceRepository


class ParallelEnrichmentService:
    def __init__(self):
        self.calls = []
        self.both_started = asyncio.Event()

    async def enrich_ip(self, source_ip):
        self.calls.append(source_ip)

        if len(self.calls) == 2:
            self.both_started.set()

        await asyncio.wait_for(
            self.both_started.wait(),
            timeout=2,
        )

        return IPIntelligenceAssessment(
            ip_address=source_ip,
            classification=IPClassification.PUBLIC,
            is_global=True,
            enrichment_status=EnrichmentStatus.COMPLETED,
            threat_score=10,
            confidence=0.9,
            reputation="low",
            assessed_at=datetime.now(timezone.utc),
        )


def test_different_alerts_can_be_enriched_concurrently(
    isolated_database,
    seeded_alert,
):
    connection = get_connection()

    try:
        cursor = connection.execute(
            """
            INSERT INTO security_alerts (
                title,
                severity,
                description,
                source_ip,
                detection_rule,
                created_at,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "Independent test alert",
                "high",
                "Second alert for concurrency testing.",
                "1.1.1.1",
                "AEGIS-TEST-002",
                datetime.now(timezone.utc).isoformat(),
                "open",
            ),
        )

        second_alert = cursor.lastrowid
        connection.commit()

    finally:
        connection.close()

    repository = IntelligenceRepository()
    enrichment_service = ParallelEnrichmentService()

    service = AlertIntelligenceService(
        enrichment_service=enrichment_service,
        repository=repository,
    )

    async def run_concurrent_requests():
        return await asyncio.gather(
            service.enrich_alert(seeded_alert, "8.8.8.8"),
            service.enrich_alert(second_alert, "1.1.1.1"),
        )

    results = asyncio.run(run_concurrent_requests())

    assert len(results) == 2

    assert all(
        result["status"] == "completed"
        for result in results
    )

    assert len(enrichment_service.calls) == 2

    first_assessment_id = (
        repository.get_assessment_by_alert_id(seeded_alert)
    )

    second_assessment_id = (
        repository.get_assessment_by_alert_id(second_alert)
    )

    assert first_assessment_id is not None
    assert second_assessment_id is not None

    assert first_assessment_id != second_assessment_id

    first_assessment = repository.get_assessment(
        first_assessment_id
    )

    second_assessment = repository.get_assessment(
        second_assessment_id
    )

    assert first_assessment["ip_address"] == "8.8.8.8"
    assert second_assessment["ip_address"] == "1.1.1.1"
