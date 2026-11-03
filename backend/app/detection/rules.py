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
    "mitre_tactic": "Credential Access",
    "mitre_technique": "T1110",
    "mitre_name": "Brute Force",
    "enabled": True
}


PORT_SCAN_RULE = {
    "rule_id": "AEGIS-NET-001",
    "name": "Network Port Scan Detection",
    "description": (
        "A source IP contacts multiple distinct destination "
        "ports on the same target within a short time window."
    ),
    "event_type": "network_connection",
    "threshold": 10,
    "window_minutes": 2,
    "severity": "high",
    "mitre_tactic": "Discovery",
    "mitre_technique": "T1046",
    "mitre_name": "Network Service Discovery",
    "enabled": True
}


HORIZONTAL_SCAN_RULE = {
    "rule_id": "AEGIS-NET-002",
    "name": "Horizontal Network Scan Detection",
    "description": (
        "A source IP contacts multiple distinct destination "
        "IP addresses on the same destination port."
    ),
    "event_type": "network_connection",
    "threshold": 10,
    "window_minutes": 2,
    "severity": "high",
    "mitre_tactic": "Discovery",
    "mitre_technique": "T1046",
    "mitre_name": "Network Service Discovery",
    "enabled": True
}



SERVICE_SWEEP_RULE = {
    "rule_id": "AEGIS-NET-003",
    "name": "Broad Network Service Discovery",
    "description": (
        "A source IP contacts numerous distinct destination "
        "IP and port combinations within a short time window."
    ),
    "event_type": "network_connection",
    "threshold": 20,
    "window_minutes": 5,
    "severity": "high",
    "mitre_tactic": "Discovery",
    "mitre_technique": "T1046",
    "mitre_name": "Network Service Discovery",
    "enabled": True
}


DETECTION_RULES = [
    BRUTE_FORCE_RULE,
    PORT_SCAN_RULE,
    HORIZONTAL_SCAN_RULE,
    SERVICE_SWEEP_RULE
]
