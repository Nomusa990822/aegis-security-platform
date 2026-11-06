
from app.intelligence.models import ProviderResult, ProviderStatus
from app.intelligence.scoring import ThreatScoringEngine


def make_result(
    provider="abuseipdb",
    status=ProviderStatus.SUCCESS,
    score=50,
    confidence=0.8,
):
    return ProviderResult(
        provider=provider,
        status=status,
        confidence=confidence,
        details={"abuse_confidence_score": score},
    )


def test_failed_provider_cannot_influence_threat_score():
    engine = ThreatScoringEngine()

    results = [
        make_result(score=20),
        make_result(
            status=ProviderStatus.ERROR,
            score=100,
        ),
    ]

    assert engine.calculate_score(results) == 20


def test_unavailable_provider_cannot_influence_confidence():
    engine = ThreatScoringEngine()

    results = [
        make_result(confidence=0.8),
        make_result(
            status=ProviderStatus.UNAVAILABLE,
            confidence=1.0,
        ),
    ]

    assert engine.calculate_confidence(results) == 0.8


def test_highest_successful_provider_score_is_selected():
    engine = ThreatScoringEngine()

    results = [
        make_result(score=30),
        make_result(score=85),
        make_result(score=55),
    ]

    assert engine.calculate_score(results) == 85


def test_out_of_range_provider_scores_are_clamped():
    engine = ThreatScoringEngine()

    results = [
        make_result(score=150),
    ]

    assert engine.calculate_score(results) == 100

    results = [
        make_result(score=-20),
    ]

    assert engine.calculate_score(results) == 0


def test_boolean_provider_score_is_rejected():
    engine = ThreatScoringEngine()

    results = [
        make_result(score=True),
    ]

    assert engine.calculate_score(results) == 0


def test_invalid_provider_score_type_is_ignored():
    engine = ThreatScoringEngine()

    results = [
        make_result(score="95"),
    ]

    assert engine.calculate_score(results) == 0


def test_unknown_provider_score_does_not_create_false_threat_score():
    engine = ThreatScoringEngine()

    results = [
        make_result(
            provider="unknown_provider",
            score=95,
        ),
    ]

    assert engine.calculate_score(results) == 0


def test_no_successful_results_produce_zero_confidence():
    engine = ThreatScoringEngine()

    results = [
        make_result(status=ProviderStatus.ERROR),
        make_result(status=ProviderStatus.UNAVAILABLE),
    ]

    assert engine.calculate_confidence(results) == 0.0


def test_reputation_is_unknown_without_successful_results():
    engine = ThreatScoringEngine()

    assert engine.determine_reputation(
        0,
        has_successful_results=False,
    ) == "unknown"


def test_reputation_thresholds_are_correct():
    engine = ThreatScoringEngine()

    assert engine.determine_reputation(24, True) == "low_risk"
    assert engine.determine_reputation(25, True) == "suspicious"
    assert engine.determine_reputation(74, True) == "suspicious"
    assert engine.determine_reputation(75, True) == "malicious"
