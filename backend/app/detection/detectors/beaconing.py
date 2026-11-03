
from datetime import datetime, timedelta, timezone
from statistics import median


def detect(connection, event, rule):
    if event.get("event_type", "").lower() != "network_connection":
        return None

    source_ip = event.get("source_ip")
    destination_ip = event.get("destination_ip")

    if not source_ip or not destination_ip:
        return None

    now = datetime.now(timezone.utc)

    cutoff = (
        now - timedelta(minutes=rule["window_minutes"])
    ).isoformat()

    rows = connection.execute(
        """
        SELECT occurred_at
        FROM security_events
        WHERE LOWER(event_type) = 'network_connection'
        AND source_ip = ?
        AND destination_ip = ?
        AND occurred_at >= ?
        ORDER BY occurred_at ASC
        """,
        (source_ip, destination_ip, cutoff)
    ).fetchall()

    timestamps = []

    for row in rows:
        try:
            timestamp = datetime.fromisoformat(row["occurred_at"])

            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)

            timestamps.append(timestamp)

        except (TypeError, ValueError):
            continue

    if len(timestamps) < rule["threshold"]:
        return None

    intervals = [
        (timestamps[i] - timestamps[i - 1]).total_seconds()
        for i in range(1, len(timestamps))
    ]

    if not intervals:
        return None

    if any(
        interval < rule["min_interval_seconds"]
        or interval > rule["max_interval_seconds"]
        for interval in intervals
    ):
        return None

    average_interval = sum(intervals) / len(intervals)
    median_interval = median(intervals)

    if median_interval <= 0:
        return None

    deviations = [
        abs(interval - median_interval)
        for interval in intervals
    ]

    variation = median(deviations) / median_interval

    if variation > rule["max_interval_variation"]:
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
            f"%Beacon destination: {destination_ip}.%"
        )
    ).fetchone()

    if existing:
        return {
            "rule_id": rule["rule_id"],
            "alert_id": existing["id"],
            "message": "Existing active beaconing alert matched",
            "created": False,
            "connection_count": len(timestamps),
            "average_interval_seconds": round(average_interval, 2),
            "interval_variation": round(variation, 4),
            "destination_ip": destination_ip,
            "severity": rule["severity"]
        }

    description = (
        f"Detected {len(timestamps)} connections with unusually "
        f"regular intervals within {rule['window_minutes']} minutes. "
        f"Source IP: {source_ip}. "
        f"Beacon destination: {destination_ip}. "
        f"Average interval: {average_interval:.2f} seconds. "
        f"Median interval: {median_interval:.2f} seconds. "
        f"Interval variation: {variation:.4f}. "
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
        "message": "Suspicious network beaconing detected",
        "created": True,
        "connection_count": len(timestamps),
        "average_interval_seconds": round(average_interval, 2),
        "interval_variation": round(variation, 4),
        "destination_ip": destination_ip,
        "severity": rule["severity"]
    }
