"""Contextual risk evaluation engine for SecureForge."""

from **future** import annotations

from datetime import datetime, timezone

from secureforge.core.findings import Finding, Severity

from .models import (
AssetImportance,
Environment,
RiskAssessment,
RiskContext,
RiskLevel,
)

class RiskEngine:
"""Evaluate contextual security risk using transparent rules."""

```
_severity_scores = {
    Severity.CRITICAL: 90.0,
    Severity.HIGH: 70.0,
    Severity.MEDIUM: 50.0,
    Severity.LOW: 25.0,
    Severity.INFO: 5.0,
}

_risk_levels = {
    "critical": RiskLevel.CRITICAL,
    "high": RiskLevel.HIGH,
    "medium": RiskLevel.MEDIUM,
    "low": RiskLevel.LOW,
    "info": RiskLevel.INFO,
}

def evaluate(
    self,
    finding: Finding,
    context: RiskContext | None = None,
) -> RiskAssessment:
    """Evaluate a finding and return a contextual risk assessment."""
    context = context or RiskContext(
        security_requirement=finding.security_requirement
    )

    score = self._severity_scores[finding.severity]
    factors: list[str] = []

    score, factor = self._apply_asset_importance(
        score,
        context.asset_importance,
    )
    if factor:
        factors.append(factor)

    score, factor = self._apply_exposure(
        score,
        context.internet_exposed,
    )
    if factor:
        factors.append(factor)

    score, factor = self._apply_authentication(
        score,
        context.authentication_required,
    )
    if factor:
        factors.append(factor)

    score, factor = self._apply_sensitive_data(
        score,
        context.sensitive_data,
    )
    if factor:
        factors.append(factor)

    score, factor = self._apply_exploit_evidence(
        score,
        context.exploit_evidence,
    )
    if factor:
        factors.append(factor)

    score = self._apply_environment(
        score,
        context.environment,
    )

    score = min(max(score, 0.0), 100.0)

    contextual_risk = self._level_from_score(score)

    explanation = self._build_explanation(
        finding,
        contextual_risk,
        score,
        factors,
    )

    return RiskAssessment(
        finding_id=finding.finding_id,
        base_severity=self._severity_to_risk_level(finding.severity),
        contextual_risk=contextual_risk,
        context=context,
        risk_score=score,
        factors=factors,
        explanation=explanation,
        evaluated_at=datetime.now(timezone.utc).isoformat(),
    )

@staticmethod
def _apply_asset_importance(
    score: float,
    importance: AssetImportance,
) -> tuple[float, str | None]:
    """Adjust risk according to asset importance."""
    adjustments = {
        AssetImportance.CRITICAL: (10.0, "critical asset"),
        AssetImportance.HIGH: (6.0, "high-importance asset"),
        AssetImportance.MEDIUM: (0.0, None),
        AssetImportance.LOW: (-5.0, "low-importance asset"),
    }

    adjustment, factor = adjustments[importance]

    return score + adjustment, factor

@staticmethod
def _apply_exposure(
    score: float,
    internet_exposed: bool,
) -> tuple[float, str | None]:
    """Adjust risk for external exposure."""
    if internet_exposed:
        return score + 10.0, "internet-exposed asset"

    return score, None

@staticmethod
def _apply_authentication(
    score: float,
    authentication_required: bool,
) -> tuple[float, str | None]:
    """Adjust risk when exploitation does not require authentication."""
    if not authentication_required:
        return score + 10.0, "no authentication required"

    return score, None

@staticmethod
def _apply_sensitive_data(
    score: float,
    sensitive_data: bool,
) -> tuple[float, str | None]:
    """Adjust risk for sensitive data exposure."""
    if sensitive_data:
        return score + 10.0, "sensitive data affected"

    return score, None

@staticmethod
def _apply_exploit_evidence(
    score: float,
    exploit_evidence: bool,
) -> tuple[float, str | None]:
    """Adjust risk when exploitation has been demonstrated."""
    if exploit_evidence:
        return score + 10.0, "exploit evidence available"

    return score, None

@staticmethod
def _apply_environment(
    score: float,
    environment: Environment,
) -> float:
    """Apply a limited environment adjustment."""
    adjustments = {
        Environment.PRODUCTION: 5.0,
        Environment.STAGING: 2.0,
        Environment.TEST: 0.0,
        Environment.DEVELOPMENT: -5.0,
        Environment.LAB: -10.0,
        Environment.UNKNOWN: 0.0,
    }

    return score + adjustments[environment]

def _level_from_score(self, score: float) -> RiskLevel:
    """Convert a numeric contextual score into a risk level."""
    if score >= 90:
        return RiskLevel.CRITICAL

    if score >= 70:
        return RiskLevel.HIGH

    if score >= 40:
        return RiskLevel.MEDIUM

    if score >= 15:
        return RiskLevel.LOW

    return RiskLevel.INFO

@staticmethod
def _severity_to_risk_level(severity: Severity) -> RiskLevel:
    """Convert finding severity into the corresponding risk level."""
    mapping = {
        Severity.CRITICAL: RiskLevel.CRITICAL,
        Severity.HIGH: RiskLevel.HIGH,
        Severity.MEDIUM: RiskLevel.MEDIUM,
        Severity.LOW: RiskLevel.LOW,
        Severity.INFO: RiskLevel.INFO,
    }

    return mapping[severity]

@staticmethod
def _build_explanation(
    finding: Finding,
    risk_level: RiskLevel,
    score: float,
    factors: list[str],
) -> str:
    """Build an explainable risk assessment."""
    if factors:
        factor_text = ", ".join(factors)
        return (
            f"{finding.finding_id} has contextual risk "
            f"{risk_level.value} with a score of {score:.1f}. "
            f"Contributing factors: {factor_text}."
        )

    return (
        f"{finding.finding_id} has contextual risk "
        f"{risk_level.value} with a score of {score:.1f}. "
        f"No additional contextual risk factors were applied."
    )
```
