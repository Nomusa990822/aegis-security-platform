
from datetime import datetime, timezone

from app.database import get_connection
from app.detection.engine import evaluate_event


def run_test():
    connection = get_connection()

    source_ip = "203.0.113.90"
    now = datetime.now(timezone.utc)

    usernames = [
        "alice",
        "bob",
        "charlie",
        "david",
        "emily"
    ]

    print("\n=== AEGIS PASSWORD SPRAYING TEST ===")

    try:
        for index, username in enumerate(usernames):
            event = {
                "event_type": "authentication",
                "source_ip": source_ip,
                "username": username,
                "outcome": "failure",
                "description": "Password spraying simulation",
                "occurred_at": now.isoformat(),
                "received_at": now.isoformat()
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
                    received_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["event_type"],
                    event["source_ip"],
                    event["username"],
                    event["outcome"],
                    event["description"],
                    event["occurred_at"],
                    event["received_at"]
                )
            )

            result = evaluate_event(connection, event)

            print(
                f"Account {index + 1}/5: {username} | "
                f"Detection: {result}"
            )

        connection.commit()

        print("\n=== PASSWORD SPRAYING TEST COMPLETE ===")

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


if __name__ == "__main__":
    run_test()
