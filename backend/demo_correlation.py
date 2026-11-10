
from datetime import datetime, timedelta, timezone

from app.database import get_connection, initialize_database
from app.detection.correlation import correlate_alerts


def main():
    initialize_database()

    connection = get_connection()
    source_ip = "198.51.100.240"

    now = datetime.now(timezone.utc)
    timestamp = now.isoformat()

    alerts = [
        (
            "Brute Force Authentication",
            "high",
            "Test brute force activity",
            source_ip,
            "AEGIS-AUTH-001",
            timestamp,
            "open",
        ),
        (
            "Password Spraying",
            "high",
            "Test password spraying activity",
            source_ip,
            "AEGIS-AUTH-002",
            (now - timedelta(minutes=2)).isoformat(),
            "open",
        ),
    ]

    try:
        for alert in alerts:
            connection.execute(
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
                alert,
            )

        connection.commit()

        result = correlate_alerts(connection, source_ip)
        connection.commit()

        print("\nCORRELATION RESULT:")
        print(result)

        if result:
            correlation = connection.execute(
                """
                SELECT *
                FROM security_correlations
                WHERE id = ?
                """,
                (result["correlation_id"],),
            ).fetchone()

            print("\nCORRELATION RECORD:")
            print(dict(correlation))

            linked_alerts = connection.execute(
                """
                SELECT COUNT(*) AS total
                FROM security_correlation_alerts
                WHERE correlation_id = ?
                """,
                (result["correlation_id"],),
            ).fetchone()

            print("\nLINKED ALERT COUNT:")
            print(linked_alerts["total"])

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


if __name__ == "__main__":
    main()
