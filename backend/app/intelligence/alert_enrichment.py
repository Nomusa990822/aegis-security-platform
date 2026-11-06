import asyncio
import ipaddress
import logging
import threading

from app.intelligence.enrichment import (
    ThreatIntelligenceEnrichmentService,
)
from app.intelligence.repository import IntelligenceRepository


logger = logging.getLogger(__name__)


def normalize_ip_address(value: str) -> str:
    """Return a canonical IP representation for reliable comparison."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except (ValueError, AttributeError):
        return str(value).strip().lower()


class AlertIntelligenceService:
    """
    Automatically enrich security alerts with IP intelligence.

    Successful assessments are reused only when the source IP matches.
    Failed, pending, and outdated assessments can be retried.

    Concurrent enrichment requests for the same alert are serialized.
    """

    def __init__(
        self,
        enrichment_service=None,
        repository=None,
    ):
        self.enrichment_service = (
            enrichment_service
            or ThreatIntelligenceEnrichmentService()
        )

        self.repository = (
            repository
            or IntelligenceRepository()
        )

        self._alert_locks = {}
        self._alert_locks_guard = threading.Lock()

    def _get_alert_lock(self, alert_id: int) -> asyncio.Lock:
        """Get or create the asynchronous lock for an alert."""
        with self._alert_locks_guard:
            if alert_id not in self._alert_locks:
                self._alert_locks[alert_id] = asyncio.Lock()

            return self._alert_locks[alert_id]

    async def enrich_alert(
        self,
        alert_id: int,
        source_ip: str,
    ) -> dict:
        """
        Serialize enrichment requests for the same alert.

        A waiting request checks the repository again after acquiring
        the lock, preventing duplicate provider calls and assessments.
        """
        lock = self._get_alert_lock(alert_id)

        async with lock:
            return await self._enrich_alert_locked(
                alert_id,
                source_ip,
            )

    async def _enrich_alert_locked(
        self,
        alert_id: int,
        source_ip: str,
    ) -> dict:
        """Perform enrichment while holding the alert lock."""

        if not source_ip:
            return {
                "status": "skipped",
                "alert_id": alert_id,
                "assessment_id": None,
                "message": "Alert has no source IP.",
            }

        try:
            requested_ip = normalize_ip_address(source_ip)

            existing_id = (
                self.repository.get_assessment_by_alert_id(
                    alert_id
                )
            )

            if existing_id is not None:
                existing_assessment = (
                    self.repository.get_assessment(
                        existing_id
                    )
                )

                if existing_assessment is not None:
                    existing_status = (
                        existing_assessment.get(
                            "enrichment_status"
                        )
                    )

                    if hasattr(existing_status, "value"):
                        existing_status = existing_status.value

                    existing_ip = existing_assessment.get(
                        "ip_address"
                    )

                    same_source_ip = (
                        existing_ip is not None
                        and normalize_ip_address(existing_ip)
                        == requested_ip
                    )

                    reusable_status = (
                        existing_status not in ("failed", "pending")
                    )

                    if reusable_status and same_source_ip:
                        return {
                            "status": "already_enriched",
                            "alert_id": alert_id,
                            "assessment_id": existing_id,
                            "message": (
                                "An intelligence assessment already "
                                "exists for this source IP."
                            ),
                        }

            assessment = (
                await self.enrichment_service.enrich_ip(
                    source_ip
                )
            )

            assessment_id = (
                self.repository.save_assessment(
                    assessment,
                    alert_id=alert_id,
                )
            )

            return {
                "status": assessment.enrichment_status,
                "alert_id": alert_id,
                "assessment_id": assessment_id,
                "threat_score": assessment.threat_score,
                "reputation": assessment.reputation,
                "message": "Alert intelligence assessment saved.",
            }

        except Exception:
            logger.exception(
                "Automatic intelligence enrichment failed for alert %s",
                alert_id,
            )

            return {
                "status": "error",
                "alert_id": alert_id,
                "assessment_id": None,
                "message": (
                    "Intelligence enrichment could not be completed."
                ),
            }
