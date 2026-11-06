from datetime import datetime, timedelta, timezone


def detect(connection, event, rule):
    """
    Detect a source IP contacting multiple distinct
    destination ports on the same destination IP
    within a configured time window.
    """

    if event.get("event_type", "").lower() != "network_connection":
        return None

    source_ip = event.get("source_ip")
    destination_ip = event.get("destination_ip")
    destination_port = event.get("destination_port")

    # Incomplete telemetry cannot trigger this rule.
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
        SELECT DISTINCT destination_port
        FROM security_events
        WHERE LOWER(event_type) = 'network_connection'
        AND source_ip = ?
        AND destination_ip = ?
        AND destination_port IS NOT NULL
        AND julianday(received_at) IS NOT NULL
        AND received_at >= ?
        ORDER BY destination_port
        """,
        (
            source_ip,
            destination_ip,
            cutoff
        )
    ).fetchall()

    ports = [row["destination_port"] for row in rows]
    port_count = len(ports)

    if port_count < rule["threshold"]:
        return None

    # Reuse an existing active alert for this
    # source-to-destination pair.
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
            f"%Destination IP: {destination_ip}.%"
        )
    ).fetchone()

    if existing:
        return {
            "rule_id": rule["rule_id"],
            "alert_id": existing["id"],
            "message": "Existing active port-scan alert matched",
            "created": False,
            "distinct_port_count": port_count,
            "destination_ip": destination_ip,
            "severity": rule["severity"]
        }

    description = (
        f"Detected {port_count} distinct destination ports "
        f"contacted within {rule['window_minutes']} minutes. "
        f"Source IP: {source_ip}. "
        f"Destination IP: {destination_ip}. "
        f"Destination ports: {', '.join(map(str, ports))}. "
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
        "message": "Port scanning activity detected",
        "created": True,
        "distinct_port_count": port_count,
        "destination_ip": destination_ip,
        "severity": rule["severity"]
    }
