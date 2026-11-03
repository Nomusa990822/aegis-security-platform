
from datetime import datetime, timedelta, timezone


def detect(connection, event, rule):
    """
    Detect password spraying: one source IP attempting
    authentication against multiple distinct accounts.
    """

    if event.get("event_type", "").lower() != "authentication":
        return None

    if event.get("outcome", "").lower() not in (
        "failure",
        "failed",
        "unsuccessful"
    ):
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
        SELECT DISTINCT username
        FROM security_events
        WHERE LOWER(event_type) = 'authentication'
        AND LOWER(outcome) IN ('failure', 'failed', 'unsuccessful')
        AND source_ip = ?
        AND username IS NOT NULL
        AND occurred_at >= ?
        """,
        (source_ip, cutoff)
    ).fetchall()

    targeted_accounts = {
        row["username"]
        for row in rows
        if row["username"]
    }

    account_count = len(targeted_accounts)

    if account_count < rule["threshold"]:
        return None

    existing = connection.execute(
        """
        SELECT id
        FROM security_alerts
        WHERE detection_rule = ?
        AND source_ip = ?
        AND status IN ('open', 'investigating')
        LIMIT 1
        """,
        (rule["rule_id"], source_ip)
    ).fetchone()

    if existing:
        return {
            "rule_id": rule["rule_id"],
            "alert_id": existing["id"],
            "message": "Existing active password spraying alert matched",
            "created": False,
            "targeted_account_count": account_count,
            "severity": rule["severity"]
        }

    description = (
        f"Detected authentication failures against "
        f"{account_count} distinct accounts from one source IP "
        f"within {rule['window_minutes']} minutes. "
        f"Source IP: {source_ip}. "
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
        "message": "Password spraying detected",
        "created": True,
        "targeted_account_count": account_count,
        "severity": rule["severity"]
    }
