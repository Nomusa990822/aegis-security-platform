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

DETECTOR_REGISTRY = {
    "AEGIS-AUTH-001": detect_brute_force,
    "AEGIS-NET-001": detect_port_scan,
    "AEGIS-NET-002": detect_horizontal_scan,
    "AEGIS-NET-003": detect_service_sweep,
    "AEGIS-NET-004": detect_beaconing
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

