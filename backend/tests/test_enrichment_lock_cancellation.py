
import asyncio
from datetime import datetime, timezone

from app.intelligence.alert_enrichment import AlertIntelligenceService
from app.intelligence.models import (
    EnrichmentStatus,
    IPClassification,
    IPIntelligenceAssessment,
)
from app.intelligence.repository import IntelligenceRepository


class BlockingEnrichmentService:
    def __init__(self):
        self.calls = 0
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def enrich_ip(self, source_ip):
        self.calls += 1
        self.started.set()

        await self.release.wait()

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


def test_cancelled_waiting_request_does_not_leak_lock_reference(
    isolated_database,
    seeded_alert,
):
    enrichment_service = BlockingEnrichmentService()

    service = AlertIntelligenceService(
        enrichment_service=enrichment_service,
        repository=IntelligenceRepository(),
    )

    async def scenario():
        holder = asyncio.create_task(
            service.enrich_alert(seeded_alert, "8.8.8.8")
        )

        await enrichment_service.started.wait()

        waiter = asyncio.create_task(
            service.enrich_alert(seeded_alert, "8.8.8.8")
        )

        await asyncio.sleep(0)

        entry = service._alert_locks[seeded_alert]
        assert entry["users"] == 2

        waiter.cancel()

        waiter_result = await asyncio.gather(
            waiter,
            return_exceptions=True,
        )

        assert isinstance(
            waiter_result[0],
            asyncio.CancelledError,
        )

        assert service._alert_locks[seeded_alert]["users"] == 1

        enrichment_service.release.set()

        holder_result = await holder

        assert holder_result["status"] == "completed"

        assert service._alert_locks == {}

    asyncio.run(scenario())


def test_cancelled_lock_holder_releases_lock_for_waiting_request(
    isolated_database,
    seeded_alert,
):
    enrichment_service = BlockingEnrichmentService()

    service = AlertIntelligenceService(
        enrichment_service=enrichment_service,
        repository=IntelligenceRepository(),
    )

    async def scenario():
        holder = asyncio.create_task(
            service.enrich_alert(seeded_alert, "8.8.8.8")
        )

        await enrichment_service.started.wait()

        waiter = asyncio.create_task(
            service.enrich_alert(seeded_alert, "8.8.8.8")
        )

        await asyncio.sleep(0)

        assert service._alert_locks[seeded_alert]["users"] == 2

        holder.cancel()

        holder_result = await asyncio.gather(
            holder,
            return_exceptions=True,
        )

        assert isinstance(
            holder_result[0],
            asyncio.CancelledError,
        )

        assert service._alert_locks[seeded_alert]["users"] == 1

        enrichment_service.release.set()

        waiter_result = await waiter

        assert waiter_result["status"] == "completed"

        assert enrichment_service.calls == 2

        assert service._alert_locks == {}

    asyncio.run(scenario())
