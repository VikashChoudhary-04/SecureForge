"""Contextual risk evaluation engine for SecureForge."""

from __future__ import annotations

from datetime import datetime, timezone

from secureforge.core.findings import Finding, Severity

from .models import (
RiskAssessment,
RiskContext,
RiskLevel,
)
from .scoring import RiskScorer

class RiskEngine:
"""Evaluate contextual security risk using transparent rules."""

```
def __init__(
    self,
    scorer: RiskScorer | None = None,
) -> None:
    self.scorer = scorer or RiskScorer()

def evaluate(
    self,
    finding: Finding,
    context: RiskContext | None = None,
) -> RiskAssessment:
    """Evaluate a finding and return a contextual risk assessment."""
    context = context or RiskContext(
        security_requirement=finding.security_requirement
    )

    score, factors = self.scorer.calculate(
        finding,
        context,
    )

    contextual_risk = self._level_from_score(
        score
    )

    explanation = self._build_explanation(
        finding,
        contextual_risk,
        score,
        factors,
    )

    return RiskAssessment(
        finding_id=finding.finding_id,
        base_severity=self._severity_to_risk_level(
            finding.severity
        ),
        contextual_risk=contextual_risk,
        context=context,
        risk_score=score,
        factors=factors,
        explanation=explanation,
        evaluated_at=datetime.now(
            timezone.utc
        ).isoformat(),
    )

@staticmethod
def _level_from_score(
    score: float,
) -> RiskLevel:
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
def _severity_to_risk_level(
    severity: Severity,
) -> RiskLevel:
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
        "No additional contextual risk factors were applied."
    )
```
