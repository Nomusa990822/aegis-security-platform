
from datetime import datetime, timedelta, timezone


SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}


def correlate_alerts(connection, source_ip):
    """
    Correlate active security alerts from the same source IP.

    A correlation requires at least two distinct detection rules
    within the configured time window.
    """

    if not source_ip:
        return None

    now = datetime.now(timezone.utc)
    window_minutes = 10

    cutoff = (
        now - timedelta(minutes=window_minutes)
    ).isoformat()

    rows = connection.execute(
        """
        SELECT *
        FROM security_alerts
        WHERE source_ip = ?
        AND status IN ('open', 'investigating')
        AND created_at >= ?
        ORDER BY created_at ASC
        """,
        (source_ip, cutoff)
    ).fetchall()

    alerts = [dict(row) for row in rows]

    distinct_rules = {
        alert["detection_rule"]
        for alert in alerts
    }

    if len(distinct_rules) < 2:
        return None

    severity = max(
        (
            alert["severity"].lower()
            for alert in alerts
        ),
        key=lambda value: SEVERITY_RANK.get(value, 0)
    )

    title = "Correlated Multi-Stage Security Activity"

    description = (
        f"Identified {len(alerts)} active alerts across "
        f"{len(distinct_rules)} distinct detection rules "
        f"within {window_minutes} minutes. "
        f"Shared source IP: {source_ip}. "
        "These alerts may represent related security activity "
        "and require analyst investigation."
    )

    existing = connection.execute(
        """
        SELECT id
        FROM security_correlations
        WHERE source_ip = ?
        AND status IN ('open', 'investigating')
        ORDER BY id DESC
        LIMIT 1
        """,
        (source_ip,)
    ).fetchone()

    if existing:
        correlation_id = existing["id"]

        for alert in alerts:
            connection.execute(
                """
                INSERT OR IGNORE INTO security_correlation_alerts (
                    correlation_id,
                    alert_id,
                    linked_at
                )
                VALUES (?, ?, ?)
                """,
                (
                    correlation_id,
                    alert["id"],
                    now.isoformat()
                )
            )

        count = connection.execute(
            """
            SELECT COUNT(*) AS total
            FROM security_correlation_alerts
            WHERE correlation_id = ?
            """,
            (correlation_id,)
        ).fetchone()["total"]

        connection.execute(
            """
            UPDATE security_correlations
            SET severity = ?,
                description = ?,
                alert_count = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                severity,
                description,
                count,
                now.isoformat(),
                correlation_id
            )
        )

        return {
            "correlation_id": correlation_id,
            "created": False,
            "alert_count": count,
            "severity": severity
        }

    cursor = connection.execute(
        """
        INSERT INTO security_correlations (
            title,
            severity,
            source_ip,
            description,
            alert_count,
            status,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            title,
            severity,
            source_ip,
            description,
            len(alerts),
            "open",
            now.isoformat(),
            now.isoformat()
        )
    )

    correlation_id = cursor.lastrowid

    for alert in alerts:
        connection.execute(
            """
            INSERT OR IGNORE INTO security_correlation_alerts (
                correlation_id,
                alert_id,
                linked_at
            )
            VALUES (?, ?, ?)
            """,
            (
                correlation_id,
                alert["id"],
                now.isoformat()
            )
        )

    return {
        "correlation_id": correlation_id,
        "created": True,
        "alert_count": len(alerts),
        "severity": severity
    }
