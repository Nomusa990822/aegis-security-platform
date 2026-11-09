from datetime import datetime, timedelta, timezone


def detect(connection, event, rule):
    """Detect a successful login after repeated failures for one account."""

    if (event.get("event_type") or "").lower() != "authentication":
        return None

    if (event.get("outcome") or "").lower() not in (
        "success", "successful",
    ):
        return None

    source_ip = event.get("source_ip")
    username = event.get("username")
    if not source_ip or not username:
        return None

    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(minutes=rule["window_minutes"])).isoformat()

    row = connection.execute(
        """
        SELECT COUNT(*) AS attempt_count
        FROM security_events
        WHERE LOWER(event_type) = 'authentication'
        AND LOWER(outcome) IN ('failure', 'failed', 'unsuccessful')
        AND source_ip = ?
        AND username = ?
        AND julianday(received_at) IS NOT NULL
        AND received_at >= ?
        """,
        (source_ip, username, cutoff),
    ).fetchone()

    attempt_count = row["attempt_count"]
    if attempt_count < rule["threshold"]:
        return None

    existing = connection.execute(
        """
        SELECT id FROM security_alerts
        WHERE detection_rule = ?
        AND source_ip = ?
        AND description LIKE ?
        AND status IN ('open', 'investigating')
        LIMIT 1
        """,
        (
            rule["rule_id"], source_ip, f"%Username: {username}.%",
        ),
    ).fetchone()

    if existing:
        return {
            "rule_id": rule["rule_id"],
            "alert_id": existing["id"],
            "message": "Existing active post-failure authentication alert matched",
            "created": False,
            "failed_attempt_count": attempt_count,
            "severity": rule["severity"],
        }

    description = (
        f"A successful authentication followed {attempt_count} failed "
        f"attempts within {rule['window_minutes']} minutes. "
        f"Source IP: {source_ip}. Username: {username}. "
        f"This sequence requires analyst verification and does not "
        f"establish account compromise. "
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
        "message": "Successful authentication followed repeated failures",
        "created": True,
        "failed_attempt_count": attempt_count,
        "severity": rule["severity"],
    }
