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
        SELECT DISTINCT destination_ip, destination_port
        FROM security_events
        WHERE LOWER(event_type) = 'network_connection'
        AND source_ip = ?
        AND destination_ip IS NOT NULL
        AND destination_port IS NOT NULL
        AND julianday(received_at) IS NOT NULL
        AND received_at >= ?
        ORDER BY destination_ip, destination_port
        """,
        (source_ip, cutoff)
    ).fetchall()

    destination_pairs = [
        (row["destination_ip"], row["destination_port"])
        for row in rows
    ]

    pair_count = len(destination_pairs)

    if pair_count < rule["threshold"]:
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
            "%Detection scope: multi-target service sweep.%"
        )
    ).fetchone()

    if existing:
        return {
            "rule_id": rule["rule_id"],
            "alert_id": existing["id"],
            "message": "Existing active service-sweep alert matched",
            "created": False,
            "destination_pair_count": pair_count,
            "severity": rule["severity"]
        }

    pair_summary = ", ".join(
        f"{ip}:{port}" for ip, port in destination_pairs
    )

    description = (
        f"Detected {pair_count} distinct destination IP/port "
        f"combinations within {rule['window_minutes']} minutes. "
        f"Source IP: {source_ip}. "
        f"Detection scope: multi-target service sweep. "
        f"Destination combinations: {pair_summary}. "
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
        "message": "Broad network service discovery detected",
        "created": True,
        "destination_pair_count": pair_count,
        "severity": rule["severity"]
    }
