"""Tests for the SecureForge contextual risk scorer."""

import pytest

from secureforge.core.findings import Finding, Severity
from secureforge.core.risk import (
AssetImportance,
Environment,
RiskContext,
)
from secureforge.core.risk.scoring import RiskScorer

def build_finding(
severity: Severity = Severity.HIGH,
) -> Finding:
"""Create a representative finding."""
return Finding(
finding_id="SF-001",
title="SQL Injection",
source="dast",
application="SecureCommerce",
asset="securecommerce-api",
endpoint="/api/products",
parameter="search",
cwe="CWE-89",
severity=severity,
description="SQL injection was confirmed.",
impact="Database queries may be manipulated.",
remediation="Use parameterized queries.",
)

def build_context(
**overrides: object,
) -> RiskContext:
"""Create a representative risk context."""
data: dict[str, object] = {
"asset_importance": AssetImportance.MEDIUM,
"internet_exposed": False,
"authentication_required": True,
"sensitive_data": False,
"exploit_evidence": False,
"environment": Environment.UNKNOWN,
}

data.update(overrides)

return RiskContext.model_validate(data)

def test_base_score_matches_severity() -> None:
"""Verify severity maps to the documented base score."""
scorer = RiskScorer()

assert scorer.base_score(
    build_finding(Severity.CRITICAL)
) == 90.0

assert scorer.base_score(
    build_finding(Severity.HIGH)
) == 70.0

assert scorer.base_score(
    build_finding(Severity.MEDIUM)
) == 50.0

assert scorer.base_score(
    build_finding(Severity.LOW)
) == 25.0

assert scorer.base_score(
    build_finding(Severity.INFO)
) == 5.0

@pytest.mark.parametrize(
("severity", "expected"),
[
(Severity.CRITICAL, 90.0),
(Severity.HIGH, 70.0),
(Severity.MEDIUM, 50.0),
(Severity.LOW, 25.0),
(Severity.INFO, 5.0),
],
)
def test_severity_score_helper(
severity: Severity,
expected: float,
) -> None:
"""Verify the static severity score helper."""
assert RiskScorer.severity_score(
severity
) == expected

def test_critical_asset_adds_ten_points() -> None:
"""Verify critical assets receive the documented adjustment."""
scorer = RiskScorer()

score, factor = scorer.apply_asset_importance(
    50.0,
    AssetImportance.CRITICAL,
)

assert score == 60.0
assert factor == "critical-importance asset"

def test_high_asset_adds_six_points() -> None:
"""Verify high-importance assets receive the documented adjustment."""
scorer = RiskScorer()

score, factor = scorer.apply_asset_importance(
    50.0,
    AssetImportance.HIGH,
)

assert score == 56.0
assert factor == "high-importance asset"

def test_medium_asset_has_no_adjustment() -> None:
"""Verify medium assets leave the score unchanged."""
scorer = RiskScorer()

score, factor = scorer.apply_asset_importance(
    50.0,
    AssetImportance.MEDIUM,
)

assert score == 50.0
assert factor is None

def test_low_asset_reduces_score_by_five() -> None:
"""Verify low-importance assets receive the documented reduction."""
scorer = RiskScorer()

score, factor = scorer.apply_asset_importance(
    50.0,
    AssetImportance.LOW,
)

assert score == 45.0
assert factor == "low-importance asset"

def test_internet_exposure_adds_ten_points() -> None:
"""Verify internet exposure increases risk."""
score, factor = RiskScorer.apply_internet_exposure(
50.0,
True,
)

assert score == 60.0
assert factor == "internet-exposed asset"

def test_no_internet_exposure_has_no_adjustment() -> None:
"""Verify internal assets receive no exposure adjustment."""
score, factor = RiskScorer.apply_internet_exposure(
50.0,
False,
)

assert score == 50.0
assert factor is None

def test_missing_authentication_adds_ten_points() -> None:
"""Verify unauthenticated exploitation increases risk."""
score, factor = RiskScorer.apply_authentication(
50.0,
False,
)

assert score == 60.0
assert factor == "no authentication required"

def test_required_authentication_has_no_adjustment() -> None:
"""Verify authentication requirements do not increase risk."""
score, factor = RiskScorer.apply_authentication(
50.0,
True,
)

assert score == 50.0
assert factor is None

def test_sensitive_data_adds_ten_points() -> None:
"""Verify sensitive-data impact increases risk."""
score, factor = RiskScorer.apply_sensitive_data(
50.0,
True,
)

assert score == 60.0
assert factor == "sensitive data affected"

def test_no_sensitive_data_has_no_adjustment() -> None:
"""Verify non-sensitive findings receive no data adjustment."""
score, factor = RiskScorer.apply_sensitive_data(
50.0,
False,
)

assert score == 50.0
assert factor is None

def test_exploit_evidence_adds_ten_points() -> None:
"""Verify confirmed exploit evidence increases risk."""
score, factor = RiskScorer.apply_exploit_evidence(
50.0,
True,
)

assert score == 60.0
assert factor == "exploit evidence available"

def test_no_exploit_evidence_has_no_adjustment() -> None:
"""Verify absent exploit evidence does not change the score."""
score, factor = RiskScorer.apply_exploit_evidence(
50.0,
False,
)

assert score == 50.0
assert factor is None

@pytest.mark.parametrize(
("environment", "adjustment"),
[
(Environment.PRODUCTION, 5.0),
(Environment.STAGING, 2.0),
(Environment.TEST, 0.0),
(Environment.DEVELOPMENT, -5.0),
(Environment.LAB, -10.0),
(Environment.UNKNOWN, 0.0),
],
)
def test_environment_adjustments(
environment: Environment,
adjustment: float,
) -> None:
"""Verify environment adjustments."""
score = RiskScorer().apply_environment(
50.0,
environment,
)

assert score == 50.0 + adjustment

def test_calculate_combines_all_contextual_factors() -> None:
"""Verify contextual factors are applied together."""
scorer = RiskScorer()

score, factors = scorer.calculate(
    build_finding(Severity.HIGH),
    build_context(
        asset_importance=AssetImportance.CRITICAL,
        internet_exposed=True,
        authentication_required=False,
        sensitive_data=True,
        exploit_evidence=True,
        environment=Environment.PRODUCTION,
    ),
)

assert score == 100.0

assert factors == [
    "critical-importance asset",
    "internet-exposed asset",
    "no authentication required",
    "sensitive data affected",
    "exploit evidence available",
]

def test_calculate_applies_environment_after_contextual_factors() -> None:
"""Verify the environment adjustment participates in the final score."""
scorer = RiskScorer()

score, factors = scorer.calculate(
    build_finding(Severity.MEDIUM),
    build_context(
        environment=Environment.PRODUCTION,
    ),
)

assert score == 55.0
assert factors == []

def test_calculate_can_reduce_lab_risk() -> None:
"""Verify lab context reduces the final score."""
scorer = RiskScorer()

score, factors = scorer.calculate(
    build_finding(Severity.MEDIUM),
    build_context(
        environment=Environment.LAB,
    ),
)

assert score == 40.0
assert factors == []

def test_calculate_returns_explainable_factors() -> None:
"""Verify contextual adjustments produce traceable factors."""
scorer = RiskScorer()

_, factors = scorer.calculate(
    build_finding(),
    build_context(
        asset_importance=AssetImportance.HIGH,
        internet_exposed=True,
        authentication_required=False,
        sensitive_data=True,
        exploit_evidence=True,
    ),
)

assert factors == [
    "high-importance asset",
    "internet-exposed asset",
    "no authentication required",
    "sensitive data affected",
    "exploit evidence available",
]

def test_clamp_limits_upper_bound() -> None:
"""Verify scores cannot exceed 100."""
assert RiskScorer.clamp(150.0) == 100.0

def test_clamp_limits_lower_bound() -> None:
"""Verify scores cannot fall below zero."""
assert RiskScorer.clamp(-25.0) == 0.0

def test_clamp_preserves_valid_score() -> None:
"""Verify valid scores remain unchanged."""
assert RiskScorer.clamp(72.5) == 72.5
