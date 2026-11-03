from app.detection.rules import DETECTION_RULES
from app.detection.detectors.brute_force import (
    detect as detect_brute_force
)


DETECTOR_REGISTRY = {
    "AEGIS-AUTH-001": detect_brute_force
}


def get_detection_rules():
    """Return the registered detection rule definitions."""
    return DETECTION_RULES


def get_detector(rule_id):
    """Retrieve the detector associated with a rule."""

    detector = DETECTOR_REGISTRY.get(rule_id)

    if detector is None:
        raise ValueError(
            f"No detector registered for rule: {rule_id}"
        )

    return detector
