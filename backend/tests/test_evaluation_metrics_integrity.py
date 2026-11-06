from app.evaluation.runner import (
    calculate_metrics,
    evaluate_dataset,
)


def test_perfect_classification_metrics():
    metrics = calculate_metrics(
        true_positives=6,
        false_positives=0,
        true_negatives=66,
        false_negatives=0,
    )

    assert metrics == {
        "true_positives": 6,
        "false_positives": 0,
        "true_negatives": 66,
        "false_negatives": 0,
        "precision": 1.0,
        "recall": 1.0,
        "f1_score": 1.0,
        "accuracy": 1.0,
    }


def test_zero_denominators_return_zero_metrics():
    metrics = calculate_metrics(
        true_positives=0,
        false_positives=0,
        true_negatives=0,
        false_negatives=0,
    )

    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["f1_score"] == 0.0
    assert metrics["accuracy"] == 0.0


def test_false_positives_reduce_precision_and_accuracy():
    metrics = calculate_metrics(
        true_positives=0,
        false_positives=3,
        true_negatives=7,
        false_negatives=0,
    )

    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["f1_score"] == 0.0
    assert metrics["accuracy"] == 0.7


def test_precision_recall_and_f1_are_calculated_correctly():
    metrics = calculate_metrics(
        true_positives=1,
        false_positives=2,
        true_negatives=6,
        false_negatives=1,
    )

    assert metrics["precision"] == 0.3333
    assert metrics["recall"] == 0.5
    assert metrics["f1_score"] == 0.4
    assert metrics["accuracy"] == 0.7


def test_metrics_are_rounded_to_four_decimal_places():
    metrics = calculate_metrics(
        true_positives=1,
        false_positives=2,
        true_negatives=0,
        false_negatives=2,
    )

    assert metrics["precision"] == 0.3333
    assert metrics["recall"] == 0.3333
    assert metrics["f1_score"] == 0.3333
    assert metrics["accuracy"] == 0.2


def test_every_detection_rule_is_evaluated_against_every_scenario():
    report = evaluate_dataset()

    scenario_count = report["evaluation"]["scenario_count"]
    rule_metrics = report["rule_metrics"]

    assert scenario_count == len(report["scenario_results"])
    assert len(rule_metrics) == report["evaluation"][
        "detection_rules_evaluated"
    ]

    for rule_id, result in rule_metrics.items():
        metrics = result["metrics"]

        evaluated_scenarios = (
            metrics["true_positives"]
            + metrics["false_positives"]
            + metrics["true_negatives"]
            + metrics["false_negatives"]
        )

        assert evaluated_scenarios == scenario_count, rule_id


def test_each_rule_has_positive_and_negative_evaluation_examples():
    report = evaluate_dataset()

    scenarios = report["scenario_results"]

    for rule_id, result in report["rule_metrics"].items():
        metrics = result["metrics"]

        expected_positive_scenarios = sum(
            scenario["expected_rule_id"] == rule_id
            for scenario in scenarios
        )

        expected_negative_scenarios = (
            len(scenarios) - expected_positive_scenarios
        )

        assert (
            metrics["true_positives"]
            + metrics["false_negatives"]
            == expected_positive_scenarios
        )

        assert (
            metrics["true_negatives"]
            + metrics["false_positives"]
            == expected_negative_scenarios
        )

        assert expected_positive_scenarios > 0
        assert expected_negative_scenarios > 0


def test_overall_confusion_matrix_matches_sum_of_rule_metrics():
    report = evaluate_dataset()

    overall = report["overall_metrics"]

    metric_names = (
        "true_positives",
        "false_positives",
        "true_negatives",
        "false_negatives",
    )

    for metric_name in metric_names:
        expected_total = sum(
            result["metrics"][metric_name]
            for result in report["rule_metrics"].values()
        )

        assert overall[metric_name] == expected_total


def test_malicious_scenarios_trigger_their_expected_rules():
    report = evaluate_dataset()

    malicious_scenarios = [
        scenario
        for scenario in report["scenario_results"]
        if scenario["category"] == "malicious"
    ]

    assert malicious_scenarios

    for scenario in malicious_scenarios:
        assert scenario["expected_rule_id"] is not None

        assert (
            scenario["expected_rule_id"]
            in scenario["detected_rule_ids"]
        ), scenario["scenario_id"]


def test_benign_scenarios_do_not_trigger_detection_rules():
    report = evaluate_dataset()

    benign_scenarios = [
        scenario
        for scenario in report["scenario_results"]
        if scenario["category"] == "benign"
    ]

    assert benign_scenarios

    for scenario in benign_scenarios:
        assert scenario["expected_rule_id"] is None
        assert scenario["detected_rule_ids"] == [], scenario["scenario_id"]


def test_evaluation_totals_match_scenario_data():
    report = evaluate_dataset()

    metadata = report["evaluation"]
    scenarios = report["scenario_results"]

    assert metadata["malicious_scenarios"] == sum(
        scenario["category"] == "malicious"
        for scenario in scenarios
    )

    assert metadata["benign_scenarios"] == sum(
        scenario["category"] == "benign"
        for scenario in scenarios
    )

    assert metadata["total_events"] == sum(
        scenario["event_count"]
        for scenario in scenarios
    )

    assert (
        metadata["malicious_scenarios"]
        + metadata["benign_scenarios"]
        == metadata["scenario_count"]
    )