
from datetime import datetime, timedelta, timezone

from app.database import get_connection
from app.detection.engine import evaluate_event


def run_test():
    connection = get_connection()

    source_ip = "203.0.113.80"
    destination_ip = "192.0.2.220"
    destination_port = 8443

    now = datetime.now(timezone.utc)

    print("\n=== AEGIS BEACONING DETECTION TEST ===")

    try:
        for index in range(6):
            occurred_at = (
                now - timedelta(seconds=(5 - index) * 10)
            ).isoformat()

            event = {
                "event_type": "network_connection",
                "source_ip": source_ip,
                "username": None,
                "outcome": "success",
                "description": "Controlled beaconing simulation",
                "occurred_at": occurred_at,
                "received_at": now.isoformat(),
                "destination_ip": destination_ip,
                "destination_port": destination_port,
                "protocol": "TCP"
            }

            connection.execute(
                """
                INSERT INTO security_events (
                    event_type,
                    source_ip,
                    username,
                    outcome,
                    description,
                    occurred_at,
                    received_at,
                    destination_ip,
                    destination_port,
                    protocol
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["event_type"],
                    event["source_ip"],
                    event["username"],
                    event["outcome"],
                    event["description"],
                    event["occurred_at"],
                    event["received_at"],
                    event["destination_ip"],
                    event["destination_port"],
                    event["protocol"]
                )
            )

            result = evaluate_event(connection, event)

            print(
                f"Connection {index + 1}/6 | "
                f"Time: {occurred_at} | "
                f"Detection: {result}"
            )

        connection.commit()

        print("\n=== TEST COMPLETE ===")

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


if __name__ == "__main__":
    run_test()
