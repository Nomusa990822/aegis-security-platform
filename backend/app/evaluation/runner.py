import json
import sqlite3
from datetime import datetime, timezone

from app.detection.engine import evaluate_event
from app.detection.registry import get_detection_rules
from app.evaluation.dataset import build_scenarios


def calculate_metrics(
    true_positives: int,
    false_positives: int,
    true_negatives: int,
    false_negatives: int,
) -> dict:
    """
    Calculate standard binary classification metrics.
    """

    precision_denominator = true_positives + false_positives
    recall_denominator = true_positives + false_negatives

    precision = (
        true_positives / precision_denominator
        if precision_denominator
        else 0.0
    )

    recall = (
        true_positives / recall_denominator
        if recall_denominator
        else 0.0
    )

    f1_score = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )

    total = (
        true_positives
        + false_positives
        + true_negatives
        + false_negatives
    )

    accuracy = (
        (true_positives + true_negatives) / total
        if total
        else 0.0
    )

    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "true_negatives": true_negatives,
        "false_negatives": false_negatives,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1_score, 4),
        "accuracy": round(accuracy, 4),
    }


def create_isolated_database():
    """
    Create an in-memory database for one evaluation scenario.

    This database is completely separate from aegis.db.
    """

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row

    connection.executescript(
        """
        CREATE TABLE security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            source_ip TEXT,
            username TEXT,
            outcome TEXT,
            description TEXT,
            occurred_at TEXT NOT NULL,
            received_at TEXT NOT NULL,
            destination_ip TEXT,
            destination_port INTEGER,
            protocol TEXT
        );

        CREATE TABLE security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            source_ip TEXT,
            detection_rule TEXT NOT NULL,
            created_at TEXT NOT NULL,
            status TEXT DEFAULT 'open'
        );
        """
    )

    return connection


def replay_scenario(scenario, replay_time):
    """
    Replay one labelled scenario through the real detection engine.
    """

    connection = create_isolated_database()

    try:
        for event in scenario.events:
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
                    "Synthetic evaluation event",
                    event["occurred_at"],
                    replay_time.isoformat(),
                    event["destination_ip"],
                    event["destination_port"],
                    event["protocol"],
                ),
            )

        connection.commit()

        final_event = scenario.events[-1]

        event_record = {
            "event_type": final_event["event_type"],
            "source_ip": final_event["source_ip"],
            "username": final_event["username"],
            "outcome": final_event["outcome"],
            "destination_ip": final_event["destination_ip"],
            "destination_port": final_event["destination_port"],
            "protocol": final_event["protocol"],
        }

        detections = evaluate_event(
            connection,
            event_record,
        )

        return {
            "scenario_id": scenario.scenario_id,
            "scenario_name": scenario.name,
            "category": scenario.category,
            "expected_rule_id": scenario.expected_rule_id,
            "detected_rule_ids": sorted(
                {
                    detection["rule_id"]
                    for detection in detections
                }
            ),
            "detections": detections,
            "event_count": len(scenario.events),
        }

    finally:
        connection.close()


def evaluate_dataset():
    """
    Evaluate all enabled detection rules against the synthetic dataset.

    Each scenario is replayed in its own isolated database.
    """

    replay_time = datetime.now(timezone.utc)

    scenarios = build_scenarios(replay_time)

    scenario_results = [
        replay_scenario(scenario, replay_time)
        for scenario in scenarios
    ]

    rules = get_detection_rules()

    rule_metrics = {}

    overall_tp = 0
    overall_fp = 0
    overall_tn = 0
    overall_fn = 0

    for rule in rules:
        rule_id = rule["rule_id"]

        tp = 0
        fp = 0
        tn = 0
        fn = 0

        for result in scenario_results:
            actual_positive = (
                result["expected_rule_id"] == rule_id
            )

            predicted_positive = (
                rule_id in result["detected_rule_ids"]
            )

            if actual_positive and predicted_positive:
                tp += 1

            elif not actual_positive and predicted_positive:
                fp += 1

            elif not actual_positive and not predicted_positive:
                tn += 1

            elif actual_positive and not predicted_positive:
                fn += 1

        metrics = calculate_metrics(
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
        )

        rule_metrics[rule_id] = {
            "rule_name": rule["name"],
            "metrics": metrics,
        }

        overall_tp += tp
        overall_fp += fp
        overall_tn += tn
        overall_fn += fn

    overall_metrics = calculate_metrics(
        true_positives=overall_tp,
        false_positives=overall_fp,
        true_negatives=overall_tn,
        false_negatives=overall_fn,
    )

    malicious_count = sum(
        result["category"] == "malicious"
        for result in scenario_results
    )

    benign_count = sum(
        result["category"] == "benign"
        for result in scenario_results
    )

    total_events = sum(
        result["event_count"]
        for result in scenario_results
    )

    return {
        "evaluation": {
            "platform": "AEGIS Security Platform",
            "evaluation_type": "Synthetic detection effectiveness",
            "generated_at": replay_time.isoformat(),
            "scenario_count": len(scenario_results),
            "malicious_scenarios": malicious_count,
            "benign_scenarios": benign_count,
            "total_events": total_events,
            "detection_rules_evaluated": len(rules),
        },
        "overall_metrics": overall_metrics,
        "rule_metrics": rule_metrics,
        "scenario_results": scenario_results,
        "limitations": [
            "Results are based on synthetic scenarios, not production telemetry.",
            "Each scenario is evaluated independently.",
            "Each malicious scenario has one designated expected detection rule.",
            "Metrics measure scenario-level detection, not event-level detection.",
            "The benchmark does not establish real-world detection effectiveness.",
        ],
    }


if __name__ == "__main__":
    report = evaluate_dataset()

    print(
        json.dumps(
            report,
            indent=4,
        )
    )
