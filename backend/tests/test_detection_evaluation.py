from app.evaluation.dataset import build_scenarios
from app.evaluation.runner import (
    calculate_metrics,
    create_isolated_database,
    evaluate_dataset,
)


def test_dataset_contains_nine_malicious_and_six_benign_scenarios():
    scenarios = build_scenarios()

    assert len(scenarios) == 15

    malicious = [
        scenario
        for scenario in scenarios
        if scenario.category == "malicious"
    ]

    benign = [
        scenario
        for scenario in scenarios
        if scenario.category == "benign"
    ]

    assert len(malicious) == 9
    assert len(benign) == 6


def test_each_malicious_scenario_has_one_expected_rule():
    scenarios = build_scenarios()

    malicious = [
        scenario
        for scenario in scenarios
        if scenario.category == "malicious"
    ]

    expected_rules = {
        "AEGIS-AUTH-001",
        "AEGIS-AUTH-002",
        "AEGIS-NET-001",
        "AEGIS-NET-002",
        "AEGIS-NET-003",
        "AEGIS-NET-004",
        "AEGIS-AUTH-003",
        "AEGIS-AUTH-004",
        "AEGIS-AUTH-005",
    }

    actual_rules = {
        scenario.expected_rule_id
        for scenario in malicious
    }

    assert actual_rules == expected_rules


def test_isolated_database_has_required_tables():
    connection = create_isolated_database()

    try:
        tables = {
            row["name"]
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                """
            ).fetchall()
        }

        assert "security_events" in tables
        assert "security_alerts" in tables

    finally:
        connection.close()


def test_metric_calculation():
    metrics = calculate_metrics(
        true_positives=8,
        false_positives=2,
        true_negatives=9,
        false_negatives=1,
    )

    assert metrics["true_positives"] == 8
    assert metrics["false_positives"] == 2
    assert metrics["true_negatives"] == 9
    assert metrics["false_negatives"] == 1

    assert metrics["precision"] == 0.8
    assert metrics["recall"] == 0.8889
    assert metrics["f1_score"] == 0.8421
    assert metrics["accuracy"] == 0.85


def test_metric_calculation_handles_zero_division():
    metrics = calculate_metrics(
        true_positives=0,
        false_positives=0,
        true_negatives=10,
        false_negatives=0,
    )

    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["f1_score"] == 0.0
    assert metrics["accuracy"] == 1.0


def test_full_detection_evaluation():
    report = evaluate_dataset()

    assert report["evaluation"]["scenario_count"] == 15
    assert report["evaluation"]["malicious_scenarios"] == 9
    assert report["evaluation"]["benign_scenarios"] == 6
    assert report["evaluation"]["detection_rules_evaluated"] == 9

    assert len(report["scenario_results"]) == 15
    assert len(report["rule_metrics"]) == 9

    for rule_id, result in report["rule_metrics"].items():
        metrics = result["metrics"]

        assert metrics["true_positives"] == 1, rule_id
        assert metrics["false_positives"] == 0, rule_id
        assert metrics["true_negatives"] == 14, rule_id
        assert metrics["false_negatives"] == 0, rule_id

        assert metrics["precision"] == 1.0, rule_id
        assert metrics["recall"] == 1.0, rule_id
        assert metrics["f1_score"] == 1.0, rule_id

    assert report["overall_metrics"]["precision"] == 1.0
    assert report["overall_metrics"]["recall"] == 1.0
    assert report["overall_metrics"]["f1_score"] == 1.0


def test_all_malicious_scenarios_trigger_their_expected_rule():
    report = evaluate_dataset()

    malicious_results = [
        result
        for result in report["scenario_results"]
        if result["category"] == "malicious"
    ]

    assert len(malicious_results) == 9

    for result in malicious_results:
        assert (
            result["expected_rule_id"]
            in result["detected_rule_ids"]
        ), result["scenario_id"]


def test_benign_scenarios_do_not_trigger_detection_rules():
    report = evaluate_dataset()

    benign_results = [
        result
        for result in report["scenario_results"]
        if result["category"] == "benign"
    ]

    assert len(benign_results) == 6

    for result in benign_results:
        assert result["detected_rule_ids"] == [], (
            result["scenario_id"],
            result["detected_rule_ids"],
        )
