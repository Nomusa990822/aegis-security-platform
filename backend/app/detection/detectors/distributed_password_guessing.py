from datetime import datetime, timedelta, timezone


def detect(connection, event, rule):
    """Detect failed attempts against one account from multiple source IPs."""

    if (event.get("event_type") or "").lower() != "authentication":
        return None

    if (event.get("outcome") or "").lower() not in (
        "failure", "failed", "unsuccessful",
    ):
        return None

    username = event.get("username")
    if not username:
        return None

    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(minutes=rule["window_minutes"])).isoformat()

    rows = connection.execute(
        """
        SELECT DISTINCT source_ip
        FROM security_events
        WHERE LOWER(event_type) = 'authentication'
        AND LOWER(outcome) IN ('failure', 'failed', 'unsuccessful')
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
        SELECT id FROM security_alerts
        WHERE detection_rule = ?
        AND description LIKE ?
        AND status IN ('open', 'investigating')
        LIMIT 1
        """,
        (rule["rule_id"], f"%Target username: {username}.%"),
    ).fetchone()

    if existing:
        return {
            "rule_id": rule["rule_id"],
            "alert_id": existing["id"],
            "message": "Existing active distributed password-guessing alert matched",
            "created": False,
            "distinct_source_count": source_count,
            "target_username": username,
            "severity": rule["severity"],
        }

    description = (
        f"Detected failed authentication attempts from {source_count} "
        f"distinct source IP addresses within {rule['window_minutes']} "
        f"minutes. Target username: {username}. "
        f"Source IPs: {', '.join(source_ips)}. "
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
            event.get("source_ip"), rule["rule_id"],
            now.isoformat(), "open",
        ),
    )
    return {
        "rule_id": rule["rule_id"],
        "alert_id": cursor.lastrowid,
        "message": "Distributed password guessing detected",
        "created": True,
        "distinct_source_count": source_count,
        "target_username": username,
        "severity": rule["severity"],
    }
