```python id="c9m4xw"
"""Security verification pipeline for SecureForge."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from secureforge.core.correlation.engine import CorrelationEngine
from secureforge.core.findings.models import Finding
from secureforge.core.policy.engine import PolicyEngine
from secureforge.core.policy.models import PolicyDecision
from secureforge.core.release_gate.engine import ReleaseGateEngine
from secureforge.core.release_gate.models import ReleaseGateDecision
from secureforge.core.release_gate.regression import (
    build_regression_gate_result,
)
from secureforge.core.risk.engine import RiskEngine
from secureforge.core.risk.models import RiskAssessment
from secureforge.regression import (
    RegressionGateDecision,
    RegressionSuiteResult,
    assess_regression_result,
    evaluate_regression_gate,
)


@dataclass(frozen=True)
class SecurityPipelineResult:
    """Complete result produced by the SecureForge security pipeline."""

    findings: list[Finding]
    risk: RiskAssessment
    policy: PolicyDecision
    regression: RegressionSuiteResult | None
    regression_gate: RegressionGateDecision | None
    release_gate: ReleaseGateDecision

    @property
    def release_allowed(self) -> bool:
        """Return whether the release is allowed."""
        return self.release_gate.release_allowed

    @property
    def release_blocked(self) -> bool:
        """Return whether the release is blocked."""
        return not self.release_allowed

    def to_dict(self) -> dict[str, Any]:
        """Serialize the pipeline result."""
        payload: dict[str, Any] = {
            "findings": [
                finding.model_dump(
                    mode="json"
                )
                for finding in self.findings
            ],
            "risk": self.risk.model_dump(
                mode="json"
            ),
            "policy": self.policy.model_dump(
                mode="json"
            ),
            "release_gate": (
                self.release_gate.model_dump(
                    mode="json"
                )
            ),
        }

        if self.regression is not None:
            payload["regression"] = (
                self.regression.model_dump(
                    mode="json"
                )
            )

        if self.regression_gate is not None:
            payload["regression_gate"] = (
                self.regression_gate.to_dict()
            )

        return payload


class SecurityPipeline:
    """Run correlation, risk, policy, regression, and release evaluation."""

    def __init__(
        self,
        *,
        correlation_engine: CorrelationEngine | None = None,
        risk_engine: RiskEngine | None = None,
        policy_engine: PolicyEngine | None = None,
        release_gate_engine: ReleaseGateEngine | None = None,
    ) -> None:
        self.correlation_engine = (
            correlation_engine
            if correlation_engine is not None
            else CorrelationEngine()
        )

        self.risk_engine = (
            risk_engine
            if risk_engine is not None
            else RiskEngine()
        )

        self.policy_engine = (
            policy_engine
            if policy_engine is not None
            else PolicyEngine()
        )

        self.release_gate_engine = (
            release_gate_engine
            if release_gate_engine is not None
            else ReleaseGateEngine()
        )

    def evaluate(
        self,
        findings: list[Finding],
        *,
        tool_errors: list[str] | None = None,
        regression: RegressionSuiteResult | None = None,
        regression_gate: RegressionGateDecision | None = None,
    ) -> SecurityPipelineResult:
        """Evaluate findings and optional regression results."""
        finding_list = list(
            findings
        )

        correlated_findings = (
            self.correlation_engine.correlate(
                finding_list
            )
        )

        risk = self.risk_engine.assess(
            correlated_findings
        )

        policy = self.policy_engine.evaluate(
            findings=correlated_findings,
            risk=risk,
            tool_errors=(
                tool_errors
                if tool_errors is not None
                else []
            ),
        )

        resolved_regression_gate = (
            self._resolve_regression_gate(
                regression=regression,
                regression_gate=regression_gate,
            )
        )

        release_regression = (
            build_regression_gate_result(
                resolved_regression_gate
            )
            if resolved_regression_gate is not None
            else None
        )

        release_gate = self.release_gate_engine.evaluate(
            risk=risk,
            policy=policy,
            regression=release_regression,
        )

        return SecurityPipelineResult(
            findings=correlated_findings,
            risk=risk,
            policy=policy,
            regression=regression,
            regression_gate=resolved_regression_gate,
            release_gate=release_gate,
        )

    @staticmethod
    def _resolve_regression_gate(
        *,
        regression: RegressionSuiteResult | None,
        regression_gate: RegressionGateDecision | None,
    ) -> RegressionGateDecision | None:
        """Resolve a regression gate from supplied results."""
        if regression_gate is not None:
            return regression_gate

        if regression is None:
            return None

        assessment = assess_regression_result(
            regression
        )

        return evaluate_regression_gate(
            assessment
        )

    @staticmethod
    def summarize(
        result: SecurityPipelineResult,
    ) -> dict[str, Any]:
        """Return a compact, serializable pipeline summary."""
        summary: dict[str, Any] = {
            "finding_count": len(
                result.findings
            ),
            "risk_score": result.risk.score,
            "highest_severity": (
                result.risk.highest_severity.value
            ),
            "policy": result.policy.policy_name,
            "release_status": (
                result.release_gate.status.value
            ),
            "release_allowed": (
                result.release_gate.release_allowed
            ),
        }

        if result.regression is not None:
            summary["regression"] = {
                "suite_id": result.regression.suite_id,
                "status": result.regression.status.value,
                "total": result.regression.total,
                "passed": result.regression.passed,
                "failed": result.regression.failed,
                "errors": result.regression.errors,
                "skipped": result.regression.skipped,
            }

        if result.regression_gate is not None:
            summary["regression_gate"] = (
                result.regression_gate.to_dict()
            )

        return summary
```
