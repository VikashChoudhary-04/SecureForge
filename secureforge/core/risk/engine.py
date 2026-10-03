from __future__ import annotations
from datetime import UTC,datetime
from secureforge.core.findings import Severity
from .models import RiskAssessment,RiskContext,RiskLevel
from .scoring import RiskScorer
class RiskEngine:
    def __init__(self,scorer=None):self.scorer=scorer or RiskScorer()
    def evaluate(self,finding,context=None):
        context=context or RiskContext(security_requirement=finding.security_requirement)
        score,factors=self.scorer.calculate(finding,context); factors=self._normalize_factors(factors); level=self._level(score)
        return RiskAssessment(finding_id=finding.finding_id,base_severity=self._severity(finding.severity),
                              contextual_risk=level,context=context,risk_score=score,factors=factors,
                              explanation=self._explain(finding,level,score,factors),evaluated_at=datetime.now(UTC).isoformat())
    @staticmethod
    def _level(score):
        if score>=90:return RiskLevel.CRITICAL
        if score>=70:return RiskLevel.HIGH
        if score>=40:return RiskLevel.MEDIUM
        if score>=15:return RiskLevel.LOW
        return RiskLevel.INFO
    @staticmethod
    def _severity(severity):
        return {Severity.CRITICAL:RiskLevel.CRITICAL,Severity.HIGH:RiskLevel.HIGH,Severity.MEDIUM:RiskLevel.MEDIUM,Severity.LOW:RiskLevel.LOW,Severity.INFO:RiskLevel.INFO}.get(severity,RiskLevel.INFO)
    @staticmethod
    def _normalize_factors(factors):
        """Normalize factor labels for stable public output."""
        return [
            "critical asset" if factor == "critical-importance asset" else factor
            for factor in factors
        ]

    @staticmethod
    def _explain(finding,level,score,factors):
        return f"{finding.finding_id} has contextual risk {level.value} with a score of {score:.1f}. "+(f"Contributing factors: {', '.join(factors)}." if factors else "No additional contextual risk factors were applied.")
