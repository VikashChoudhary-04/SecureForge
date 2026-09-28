"""Transparent contextual risk scoring rules for SecureForge."""

from __future__ import annotations

from secureforge.core.findings import Finding, Severity

from .models import AssetImportance, Environment, RiskContext

class RiskScorer:
"""Calculate contextual risk scores using explicit adjustments."""

```
SEVERITY_SCORES: dict[Severity, float] = {
    Severity.CRITICAL: 90.0,
    Severity.HIGH: 70.0,
    Severity.MEDIUM: 50.0,
    Severity.LOW: 25.0,
    Severity.INFO: 5.0,
}

ASSET_ADJUSTMENTS: dict[AssetImportance, float] = {
    AssetImportance.CRITICAL: 10.0,
    AssetImportance.HIGH: 6.0,
    AssetImportance.MEDIUM: 0.0,
    AssetImportance.LOW: -5.0,
}

ENVIRONMENT_ADJUSTMENTS: dict[Environment, float] = {
    Environment.PRODUCTION: 5.0,
    Environment.STAGING: 2.0,
    Environment.TEST: 0.0,
    Environment.DEVELOPMENT: -5.0,
    Environment.LAB: -10.0,
    Environment.UNKNOWN: 0.0,
}

def base_score(
    self,
    finding: Finding,
) -> float:
    """Return the numeric score associated with severity."""
    return self.SEVERITY_SCORES[
        finding.severity
    ]

def calculate(
    self,
    finding: Finding,
    context: RiskContext,
) -> tuple[float, list[str]]:
    """Calculate a contextual score and explainable factors."""
    score = self.base_score(finding)

    factors: list[str] = []

    score, factor = self.apply_asset_importance(
        score,
        context.asset_importance,
    )

    if factor:
        factors.append(factor)

    score, factor = self.apply_internet_exposure(
        score,
        context.internet_exposed,
    )

    if factor:
        factors.append(factor)

    score, factor = self.apply_authentication(
        score,
        context.authentication_required,
    )

    if factor:
        factors.append(factor)

    score, factor = self.apply_sensitive_data(
        score,
        context.sensitive_data,
    )

    if factor:
        factors.append(factor)

    score, factor = self.apply_exploit_evidence(
        score,
        context.exploit_evidence,
    )

    if factor:
        factors.append(factor)

    score = self.apply_environment(
        score,
        context.environment,
    )

    return self.clamp(score), factors

def apply_asset_importance(
    self,
    score: float,
    importance: AssetImportance,
) -> tuple[float, str | None]:
    """Apply the configured asset-importance adjustment."""
    adjustment = self.ASSET_ADJUSTMENTS[
        importance
    ]

    if adjustment == 0:
        return score, None

    if adjustment > 0:
        return (
            score + adjustment,
            f"{importance.value}-importance asset",
        )

    return (
        score + adjustment,
        f"{importance.value}-importance asset",
    )

@staticmethod
def apply_internet_exposure(
    score: float,
    internet_exposed: bool,
) -> tuple[float, str | None]:
    """Increase risk for internet-exposed assets."""
    if not internet_exposed:
        return score, None

    return (
        score + 10.0,
        "internet-exposed asset",
    )

@staticmethod
def apply_authentication(
    score: float,
    authentication_required: bool,
) -> tuple[float, str | None]:
    """Increase risk when authentication is not required."""
    if authentication_required:
        return score, None

    return (
        score + 10.0,
        "no authentication required",
    )

@staticmethod
def apply_sensitive_data(
    score: float,
    sensitive_data: bool,
) -> tuple[float, str | None]:
    """Increase risk when sensitive data is affected."""
    if not sensitive_data:
        return score, None

    return (
        score + 10.0,
        "sensitive data affected",
    )

@staticmethod
def apply_exploit_evidence(
    score: float,
    exploit_evidence: bool,
) -> tuple[float, str | None]:
    """Increase risk when exploitation has been demonstrated."""
    if not exploit_evidence:
        return score, None

    return (
        score + 10.0,
        "exploit evidence available",
    )

def apply_environment(
    self,
    score: float,
    environment: Environment,
) -> float:
    """Apply the configured environment adjustment."""
    return score + self.ENVIRONMENT_ADJUSTMENTS[
        environment
    ]

@staticmethod
def clamp(
    score: float,
) -> float:
    """Keep risk scores inside the supported 0-100 range."""
    return min(
        max(score, 0.0),
        100.0,
    )

@staticmethod
def severity_score(
    severity: Severity,
) -> float:
    """Return the configured score for a severity."""
    return RiskScorer.SEVERITY_SCORES[
        severity
    ]
```
