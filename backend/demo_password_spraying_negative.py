
from datetime import datetime, timezone

from app.database import get_connection
from app.detection.engine import evaluate_event


def run_test():
    connection = get_connection()

    source_ip = "203.0.113.91"
    username = "single_target_account"
    now = datetime.now(timezone.utc)

    print("\n=== AEGIS PASSWORD SPRAYING NEGATIVE TEST ===")

    try:
        for index in range(6):
            event = {
                "event_type": "authentication",
                "source_ip": source_ip,
                "username": username,
                "outcome": "failure",
                "description": "Repeated single-account failure simulation",
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

            password_spraying_matches = [
                detection
                for detection in result
                if detection.get("rule_id") == "AEGIS-AUTH-002"
            ]

            print(
                f"Attempt {index + 1}/6 | "
                f"Password spraying: {password_spraying_matches}"
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
