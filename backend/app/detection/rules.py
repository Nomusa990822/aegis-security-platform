BRUTE_FORCE_RULE = {
    "rule_id": "AEGIS-AUTH-001",
    "name": "Brute Force Authentication Detection",
    "description": (
        "Multiple failed authentication attempts "
        "from the same source against the same account."
    ),
    "event_type": "authentication",
    "threshold": 5,
    "window_minutes": 5,
    "severity": "high",
    "mitre_technique": "T1110",
    "mitre_name": "Brute Force",
    "enabled": True
}
