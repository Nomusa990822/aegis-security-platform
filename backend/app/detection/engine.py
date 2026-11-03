from app.detection.rules import BRUTE_FORCE_RULE
from app.detection.registry import (
    get_detection_rules,
    get_detector
)


def evaluate_event(connection, event):
    """
    Evaluate a security event against all enabled,
    registered detection rules.

    Returns a list containing every detection match.
    """

    detections = []

    for rule in get_detection_rules():

        if not rule.get("enabled", False):
            continue

        detector = get_detector(rule["rule_id"])

        result = detector(
            connection,
            event,
            rule
        )

        if result is not None:
            detections.append(result)

    return detections


def detect_brute_force(connection, event):
    """
    Backward-compatible brute-force detection interface.
    """

    if not BRUTE_FORCE_RULE.get("enabled", False):
        return None

    detector = get_detector(BRUTE_FORCE_RULE["rule_id"])

    return detector(
        connection,
        event,
        BRUTE_FORCE_RULE
    )

