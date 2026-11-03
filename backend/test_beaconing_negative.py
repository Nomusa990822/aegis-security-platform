
from datetime import datetime, timedelta, timezone

from app.database import get_connection
from app.detection.engine import evaluate_event


def run_test():
    connection = get_connection()

    source_ip = "203.0.113.81"
    destination_ip = "192.0.2.221"
    destination_port = 8443

    now = datetime.now(timezone.utc)

    # Deliberately irregular intervals:
    # 10, 45, 8, 60, 12 seconds
    offsets = [135, 125, 80, 72, 12, 0]

    print("\n=== AEGIS BEACONING NEGATIVE TEST ===")

    try:
        for index, offset in enumerate(offsets):
            occurred_at = (
                now - timedelta(seconds=offset)
            ).isoformat()

            event = {
                "event_type": "network_connection",
                "source_ip": source_ip,
                "username": None,
                "outcome": "success",
                "description": "Irregular connection simulation",
                "occurred_at": occurred_at,
                "received_at": now.isoformat(),
                "destination_ip": destination_ip,
                "destination_port": destination_port,
                "protocol": "TCP"
            }

            connection.execute(
                """
                INSERT INTO security_events (
                    event_type, source_ip, username, outcome,
                    description, occurred_at, received_at,
                    destination_ip, destination_port, protocol
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
                f"Detection: {result}"
            )

        connection.commit()

        print("\n=== NEGATIVE TEST COMPLETE ===")

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


if __name__ == "__main__":
    run_test()
