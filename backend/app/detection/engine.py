from datetime import datetime, timezone, timedelta

from app.detection.rules import BRUTE_FORCE_RULE


def detect_brute_force(connection, event):

    rule = BRUTE_FORCE_RULE

    if not rule["enabled"]:
        return None

    if event["event_type"].lower() != "authentication":
        return None

    if (event["outcome"] or "").lower() != "failure":
        return None

    source_ip = event["source_ip"]
    username = event["username"]

    if not source_ip or not username:
        return None

    now = datetime.now(timezone.utc)

    cutoff = (
        now - timedelta(minutes=rule["window_minutes"])
    ).isoformat()

    # Retrieve recent failed authentication attempts.
    rows = connection.execute(
        """
        SELECT id, received_at
        FROM security_events
        WHERE event_type = ?
        AND LOWER(outcome) = 'failure'
        AND source_ip = ?
        AND username = ?
        AND received_at >= ?
        """,
        (
            "authentication",
            source_ip,
            username,
            cutoff
        )
    ).fetchall()

    attempt_count = len(rows)

    if attempt_count < rule["threshold"]:
        return None

    # Prevent duplicate open alerts for the same detection.
    existing = connection.execute(
        """
        SELECT id
        FROM security_alerts
        WHERE detection_rule = ?
        AND source_ip = ?
        AND description LIKE ?
        AND status = 'open'
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
            "alert_id": existing["id"],
            "message": "Existing alert updated by new event",
            "created": False
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
        "alert_id": cursor.lastrowid,
        "message": "Brute force activity detected",
        "created": True,
        "attempt_count": attempt_count,
        "severity": rule["severity"]
    }
