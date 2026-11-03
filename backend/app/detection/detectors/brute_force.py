from datetime import datetime, timedelta, timezone


def detect(connection, event, rule):
    """
    Detect repeated failed authentication attempts
    from the same source IP against the same username.
    """

    if event.get("event_type", "").lower() != rule["event_type"]:
        return None

    if (event.get("outcome") or "").lower() != "failure":
        return None

    source_ip = event.get("source_ip")
    username = event.get("username")

    if not source_ip or not username:
        return None

    now = datetime.now(timezone.utc)

    cutoff = (
        now - timedelta(minutes=rule["window_minutes"])
    ).isoformat()

    rows = connection.execute(
        """
        SELECT id
        FROM security_events
        WHERE LOWER(event_type) = ?
        AND LOWER(outcome) = 'failure'
        AND source_ip = ?
        AND username = ?
        AND received_at >= ?
        """,
        (
            rule["event_type"],
            source_ip,
            username,
            cutoff
        )
    ).fetchall()

    attempt_count = len(rows)

    if attempt_count < rule["threshold"]:
        return None

    # Reuse an existing active alert instead of
    # creating duplicate incidents.
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
            f"%Username: {username}%"
        )
    ).fetchone()

    if existing:
        return {
            "rule_id": rule["rule_id"],
            "alert_id": existing["id"],
            "message": "Existing active alert matched",
            "created": False,
            "attempt_count": attempt_count,
            "severity": rule["severity"]
        }

    description = (
        f"Detected {attempt_count} failed authentication attempts "
        f"within {rule['window_minutes']} minutes. "
        f"Source IP: {source_ip}. "
        f"Username: {username}. "
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
        "message": "Brute force activity detected",
        "created": True,
        "attempt_count": attempt_count,
        "severity": rule["severity"]
    }
