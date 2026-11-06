
import pytest
from pydantic import ValidationError

from app.intelligence.models import (
    ProviderResult,
    ProviderStatus,
)


@pytest.mark.parametrize(
    "confidence",
    [-0.1, 1.1, 5, -10],
)
def test_provider_confidence_outside_valid_range_is_rejected(
    confidence,
):
    with pytest.raises(ValidationError):
        ProviderResult(
            provider="test_provider",
            status=ProviderStatus.SUCCESS,
            confidence=confidence,
        )


@pytest.mark.parametrize(
    "invalid_status",
    [
        "unknown",
        "successful",
        "malicious",
        "",
    ],
)
def test_invalid_provider_status_is_rejected(invalid_status):
    with pytest.raises(ValidationError):
        ProviderResult(
            provider="test_provider",
            status=invalid_status,
        )


def test_valid_provider_result_preserves_expected_fields():
    result = ProviderResult(
        provider="test_provider",
        status=ProviderStatus.SUCCESS,
        reputation="suspicious",
        confidence=0.85,
        categories=["port_scanning", "brute_force"],
        details={"reports": 12},
    )

    assert result.provider == "test_provider"
    assert result.status == ProviderStatus.SUCCESS
    assert result.confidence == 0.85

    assert result.categories == [
        "port_scanning",
        "brute_force",
    ]

    assert result.details["reports"] == 12


def test_provider_result_uses_safe_defaults():
    result = ProviderResult(
        provider="test_provider",
        status=ProviderStatus.UNAVAILABLE,
    )

    assert result.confidence == 0.0
    assert result.categories == []
    assert result.details == {}
    assert result.error is None
