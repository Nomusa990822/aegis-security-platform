from datetime import datetime, timedelta, timezone


def detect(connection, event, rule):
    if event.get("event_type", "").lower() != "network_connection":
        return None

    source_ip = event.get("source_ip")
    destination_ip = event.get("destination_ip")
    destination_port = event.get("destination_port")

    if not source_ip or not destination_ip:
        return None

    if destination_port is None:
        return None

    now = datetime.now(timezone.utc)

    cutoff = (
        now - timedelta(minutes=rule["window_minutes"])
    ).isoformat()

    rows = connection.execute(
        """
        SELECT DISTINCT destination_ip
        FROM security_events
        WHERE LOWER(event_type) = 'network_connection'
        AND source_ip = ?
        AND destination_port = ?
        AND destination_ip IS NOT NULL
        AND julianday(received_at) IS NOT NULL
        AND received_at >= ?
        ORDER BY destination_ip
        """,
        (source_ip, destination_port, cutoff)
    ).fetchall()

    destinations = [
        row["destination_ip"] for row in rows
    ]

    destination_count = len(destinations)

    if destination_count < rule["threshold"]:
        return None

    existing = connection.execute(
        """
        SELECT id
        FROM security_alerts
        WHERE detection_rule = ?
        AND source_ip = ?
        AND description LIKE ?
        AND status IN ('open', 'investigating')
        LIMIT 1
        """,
        (
            rule["rule_id"],
            source_ip,
            f"%Destination port: {destination_port}.%"
        )
    ).fetchone()

    if existing:
        return {
            "rule_id": rule["rule_id"],
            "alert_id": existing["id"],
            "message": "Existing active horizontal-scan alert matched",
            "created": False,
            "destination_count": destination_count,
            "destination_port": destination_port,
            "severity": rule["severity"]
        }

    description = (
        f"Detected {destination_count} distinct destination IP "
        f"addresses contacted within {rule['window_minutes']} minutes. "
        f"Source IP: {source_ip}. "
        f"Destination port: {destination_port}. "
        f"Destination IPs: {', '.join(destinations)}. "
        f"MITRE ATT&CK: {rule['mitre_technique']} "
        f"({rule['mitre_name']})."
    )

    cursor = connection.execute(
        """
        INSERT INTO security_alerts (
            title,
            severity,
            description,
            source_ip,
            detection_rule,
            created_at,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            rule["name"],
            rule["severity"],
            description,
            source_ip,
            rule["rule_id"],
            now.isoformat(),
            "open"
        )
    )

    return {
        "rule_id": rule["rule_id"],
        "alert_id": cursor.lastrowid,
        "message": "Horizontal network scan detected",
        "created": True,
        "destination_count": destination_count,
        "destination_port": destination_port,
        "severity": rule["severity"]
    }
