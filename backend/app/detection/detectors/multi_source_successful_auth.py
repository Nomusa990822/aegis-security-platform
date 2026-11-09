from datetime import datetime, timedelta, timezone


def detect(connection, event, rule):
    """Detect successful access to one account from multiple source IPs."""

    if (event.get("event_type") or "").lower() != rule["event_type"]:
        return None

    if (event.get("outcome") or "").lower() not in (
        "success", "successful",
    ):
        return None

    username = event.get("username")
    source_ip = event.get("source_ip")
    if not username or not source_ip:
        return None

    now = datetime.now(timezone.utc)
    cutoff = (
        now - timedelta(minutes=rule["window_minutes"])
    ).isoformat()

    rows = connection.execute(
        """
        SELECT DISTINCT source_ip
        FROM security_events
        WHERE LOWER(event_type) = 'authentication'
        AND LOWER(outcome) IN ('success', 'successful')
        AND username = ?
        AND source_ip IS NOT NULL
        AND TRIM(source_ip) != ''
        AND julianday(received_at) IS NOT NULL
        AND received_at >= ?
        """,
        (username, cutoff),
    ).fetchall()

    source_ips = sorted({row["source_ip"] for row in rows})
    source_count = len(source_ips)

    if source_count < rule["threshold"]:
        return None

    existing = connection.execute(
        """
        SELECT id
        FROM security_alerts
        WHERE detection_rule = ?
        AND description LIKE ?
        AND status IN ('open', 'investigating')
        LIMIT 1
        """,
        (rule["rule_id"], f"%Username: {username}.%"),
    ).fetchone()

    if existing:
        return {
            "rule_id": rule["rule_id"],
            "alert_id": existing["id"],
            "message": "Existing active multi-source authentication alert matched",
            "created": False,
            "distinct_source_count": source_count,
            "username": username,
            "severity": rule["severity"],
        }

    description = (
        f"Successful authentication for one account was observed from "
        f"{source_count} distinct source IP addresses within "
        f"{rule['window_minutes']} minutes. Username: {username}. "
        f"Source IPs: {', '.join(source_ips)}. Shared networks, VPNs, "
        f"proxies, and legitimate account use can produce this pattern; "
        f"analyst verification is required. "
        f"MITRE ATT&CK: {rule['mitre_technique']} "
        f"({rule['mitre_name']})."
    )

    cursor = connection.execute(
        """
        INSERT INTO security_alerts (
            title, severity, description, source_ip,
            detection_rule, created_at, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            rule["name"], rule["severity"], description,
            source_ip, rule["rule_id"], now.isoformat(), "open",
        ),
    )

    return {
        "rule_id": rule["rule_id"],
        "alert_id": cursor.lastrowid,
        "message": "Successful authentication observed from multiple source IPs",
        "created": True,
        "distinct_source_count": source_count,
        "username": username,
        "severity": rule["severity"],
    }
