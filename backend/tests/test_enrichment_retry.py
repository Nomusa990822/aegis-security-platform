
from datetime import datetime, timezone

from app.intelligence.alert_enrichment import AlertIntelligenceService
from app.intelligence.models import (
    EnrichmentStatus,
    IPClassification,
    IPIntelligenceAssessment,
)


class MockEnrichmentService:
    def __init__(self):
        self.calls = 0

    async def enrich_ip(self, source_ip):
        self.calls += 1

        if self.calls == 1:
            return IPIntelligenceAssessment(
                ip_address=source_ip,
                classification=IPClassification.PUBLIC,
                is_global=True,
                enrichment_status=EnrichmentStatus.FAILED,
                threat_score=0,
                confidence=0.0,
                reputation="unknown",
                accessed_at=datetime.now(timezone.utc),
            )

        return IPIntelligenceAssessment(
            ip_address=source_ip,
            classification=IPClassification.PUBLIC,
            is_global=True,
            enrichment_status=EnrichmentStatus.COMPLETED,
            threat_score=10,
            confidence=0.9,
            reputation="low",
            accessed_at=datetime.now(timezone.utc),
        )


class MockRepository:
    def __init__(self):
        self.assessments = []
        self.next_id = 1

    def get_assessment_by_alert_id(self, alert_id):
        for assessment in reversed(self.assessments):
            if assessment["alert_id"] == alert_id:
                return assessment["id"]

        return None

    def get_assessment_status(self, assessment_id):
        for assessment in self.assessments:
            if assessment["id"] == assessment_id:
                return assessment["status"]

        return None

    def save_assessment(self, assessment, alert_id=None):
        assessment_id = self.next_id
        self.next_id += 1

        self.assessments.append(
            {
                "id": assessment_id,
                "alert_id": alert_id,
                "status": assessment.enrichment_status,
            }
        )

        return assessment_id


def test_failed_enrichment_can_be_retried():
    enrichment_service = MockEnrichmentService()
    repository = MockRepository()

    service = AlertIntelligenceService(
        enrichment_service=enrichment_service,
        repository=repository,
    )

    import asyncio

    first_result = asyncio.run(
        service.enrich_alert(
            alert_id=100,
            source_ip="8.8.8.8",
        )
    )

    assert first_result["status"] == "failed"
    assert enrichment_service.calls == 1

    second_result = asyncio.run(
        service.enrich_alert(
            alert_id=100,
            source_ip="8.8.8.8",
        )
    )

    assert enrichment_service.calls == 2
    assert second_result["status"] == "completed"
    assert second_result["assessment_id"] == 2

    assert len(repository.assessments) == 2
