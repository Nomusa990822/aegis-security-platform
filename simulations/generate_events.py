import json
import urllib.request
import urllib.error
import time

API_URL = "http://localhost:8000/api/v1/events"

TEST_SCENARIO = {
    "event_type": "authentication",
    "source_ip": "192.0.2.55",
    "username": "admin_test",
    "outcome": "failure",
    "description": "Controlled brute-force detection simulation"
}


def send_event(attempt):

    payload = json.dumps(TEST_SCENARIO).encode("utf-8")

    request = urllib.request.Request(
        API_URL,
        data=payload,
        headers={
            "Content-Type": "application/json"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(request) as response:

            result = json.loads(response.read())

            print(f"\nAttempt {attempt}")
            print(f"Event ID: {result['event_id']}")
            print(f"Detection: {result['detection']}")

    except urllib.error.URLError as error:
        print(f"Request failed: {error}")


def main():

    print("AEGIS Controlled Attack Simulation")
    print("----------------------------------")

    for attempt in range(1, 6):

        send_event(attempt)
        time.sleep(0.5)

    print("\nSimulation complete.")
    print("Check /api/v1/alerts for the generated alert.")


if __name__ == "__main__":
    main()
