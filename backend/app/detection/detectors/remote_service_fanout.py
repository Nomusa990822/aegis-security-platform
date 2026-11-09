from datetime import datetime, timedelta, timezone


def detect(connection, event, rule):
    """Detect rapid fan-out across common remote-administration ports."""

    if (event.get("event_type") or "").lower() != rule["event_type"]:
        return None

    source_ip = event.get("source_ip")
    destination_ip = event.get("destination_ip")
    destination_port = event.get("destination_port")
    remote_ports = tuple(rule["remote_service_ports"])

    if not source_ip or not destination_ip:
        return None

    if destination_port not in remote_ports:
        return None

    now = datetime.now(timezone.utc)
    cutoff = (
        now - timedelta(minutes=rule["window_minutes"])
    ).isoformat()

    placeholders = ", ".join("?" for _ in remote_ports)
    rows = connection.execute(
        f"""
        SELECT DISTINCT destination_ip
        FROM security_events
        WHERE LOWER(event_type) = 'network_connection'
        AND source_ip = ?
        AND destination_port IN ({placeholders})
        AND destination_ip IS NOT NULL
        AND TRIM(destination_ip) != ''
        AND julianday(received_at) IS NOT NULL
        AND received_at >= ?
        ORDER BY destination_ip
        """,
        (source_ip, *remote_ports, cutoff),
    ).fetchall()

    destinations = [row["destination_ip"] for row in rows]
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
            "%Detection scope: remote-service fan-out.%",
        ),
    ).fetchone()

    if existing:
        return {
            "rule_id": rule["rule_id"],
            "alert_id": existing["id"],
            "message": "Existing active remote-service fan-out alert matched",
            "created": False,
            "destination_count": destination_count,
            "remote_service_ports": list(remote_ports),
            "severity": rule["severity"],
        }

    description = (
        f"Source contacted {destination_count} distinct destination hosts "
        f"over configured remote-administration ports within "
        f"{rule['window_minutes']} minutes. Source IP: {source_ip}. "
        f"Remote-service ports: {', '.join(str(port) for port in remote_ports)}. "
        f"Destination IPs: {', '.join(destinations)}. "
        f"Detection scope: remote-service fan-out. "
        f"Port numbers alone do not confirm the service or malicious intent; "
        f"verify asset ownership and authorised administration activity. "
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
            rule["name"],
            rule["severity"],
            description,
            source_ip,
            rule["rule_id"],
            now.isoformat(),
            "open",
        ),
    )

    return {
        "rule_id": rule["rule_id"],
        "alert_id": cursor.lastrowid,
        "message": "Remote-service connection fan-out detected",
        "created": True,
        "destination_count": destination_count,
        "remote_service_ports": list(remote_ports),
        "severity": rule["severity"],
    }
