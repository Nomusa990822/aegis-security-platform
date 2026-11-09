from app.detection.rules import DETECTION_RULES
from app.detection.detectors.brute_force import (
    detect as detect_brute_force
)
from app.detection.detectors.port_scan import (
    detect as detect_port_scan
)
from app.detection.detectors.horizontal_scan import detect as detect_horizontal_scan
from app.detection.detectors.service_sweep import detect as detect_service_sweep
from app.detection.detectors.beaconing import detect as detect_beaconing
from app.detection.detectors.password_spraying import (
    detect as detect_password_spraying
)
from app.detection.detectors.distributed_password_guessing import (
    detect as detect_distributed_password_guessing
)
from app.detection.detectors.auth_success_after_failures import (
    detect as detect_auth_success_after_failures
)
from app.detection.detectors.remote_service_fanout import (
    detect as detect_remote_service_fanout
)
from app.detection.detectors.multi_source_successful_auth import (
    detect as detect_multi_source_successful_auth
)

DETECTOR_REGISTRY = {
    "AEGIS-AUTH-001": detect_brute_force,
    "AEGIS-NET-001": detect_port_scan,
    "AEGIS-NET-002": detect_horizontal_scan,
    "AEGIS-NET-003": detect_service_sweep,
    "AEGIS-NET-004": detect_beaconing,
    "AEGIS-AUTH-002": detect_password_spraying,
    "AEGIS-AUTH-003": detect_distributed_password_guessing,
    "AEGIS-AUTH-004": detect_auth_success_after_failures,
    "AEGIS-AUTH-005": detect_multi_source_successful_auth,
    "AEGIS-NET-005": detect_remote_service_fanout,
}


def get_detection_rules():
    """Return registered detection rule definitions."""
    return DETECTION_RULES


def get_detector(rule_id):
    """Retrieve the detector associated with a rule."""

    detector = DETECTOR_REGISTRY.get(rule_id)

    if detector is None:
        raise ValueError(
            f"No detector registered for rule: {rule_id}"
        )

    return detector

