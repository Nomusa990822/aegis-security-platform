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
    Unused per-alert locks are removed safely.
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

    def _register_alert_lock(self, alert_id: int) -> asyncio.Lock:
        """
        Register a request against an alert lock.

        The user count includes both the current lock holder
        and requests waiting to acquire the lock.
        """
        with self._alert_locks_guard:
            entry = self._alert_locks.get(alert_id)

            if entry is None:
                entry = {
                    "lock": asyncio.Lock(),
                    "users": 0,
                }
                self._alert_locks[alert_id] = entry

            entry["users"] += 1

            return entry["lock"]

    def _release_alert_lock_reference(self, alert_id: int) -> None:
        """Remove a lock only after its final registered request exits."""
        with self._alert_locks_guard:
            entry = self._alert_locks.get(alert_id)

            if entry is None:
                return

            entry["users"] -= 1

            if entry["users"] == 0:
                del self._alert_locks[alert_id]

    async def enrich_alert(
        self,
        alert_id: int,
        source_ip: str,
    ) -> dict:
        """
        Serialize enrichment requests for the same alert.

        Waiting requests check the repository again after acquiring
        the lock, preventing duplicate provider calls and assessments.
        """
        lock = self._register_alert_lock(alert_id)

        try:
            async with lock:
                return await self._enrich_alert_locked(
                    alert_id,
                    source_ip,
                )
        finally:
            self._release_alert_lock_reference(alert_id)

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
