```python id="5w8k2r"
"""End-to-end security verification pipeline for SecureForge."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from secureforge.core.correlation.engine import CorrelationEngine
from secureforge.core.findings.models import Finding
from secureforge.core.policy.engine import PolicyEngine
from secureforge.core.policy.models import PolicyDecision
from secureforge.core.release_gate.engine import ReleaseGateEngine
from secureforge.core.release_gate.models import ReleaseGateDecision
from secureforge.core.risk.engine import RiskEngine
from secureforge.core.risk.models import RiskAssessment
from secureforge.regression.engine import RegressionEngine
from secureforge.regression.gate import RegressionGateDecision
from secureforge.regression.models import RegressionSuiteResult
from secureforge.validation.engine import ValidationEngine
from secureforge.validation.gate import (
    ValidationGateDecision,
    evaluate_validation_run,
)
from secureforge.validation.models import (
    ValidationRequest,
    ValidationResult,
    ValidationSummary,
)
from secureforge.validation.runner import ValidationRun
from secureforge.validation.serialization import (
    gate_decision_to_dict,
    validation_result_to_dict,
    validation_summary_to_dict,
)
from secureforge.validation.service import ValidationService


@dataclass(frozen=True)
class SecurityPipelineResult:
    """Complete result produced by the security pipeline."""

    findings: list[Finding]
    risk: RiskAssessment
    policy: PolicyDecision
    regression: RegressionSuiteResult | None
    regression_gate: RegressionGateDecision | None
    release_gate: ReleaseGateDecision
    validation: ValidationSummary | None = None
    validation_gate: ValidationGateDecision | None = None
    validation_results: list[ValidationResult] | None = None

    @property
    def release_allowed(self) -> bool:
        """Return whether the release gate allows progression."""
        return self.release_gate.release_allowed

    @property
    def release_blocked(self) -> bool:
        """Return whether the release is blocked."""
        return not self.release_allowed

    @property
    def validation_completed(self) -> bool:
        """Return whether validation was executed."""
        return self.validation is not None

    @property
    def validation_blocked(self) -> bool:
        """Return whether validation blocks progression."""
        return (
            self.validation_gate is not None
            and self.validation_gate.blocked
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the complete pipeline result."""
        return {
            "findings": [
                finding.model_dump(mode="json")
                for finding in self.findings
            ],
            "risk": self.risk.model_dump(mode="json"),
            "policy": self.policy.model_dump(mode="json"),
            "regression": (
                self.regression.model_dump(mode="json")
                if self.regression is not None
                else None
            ),
            "regression_gate": (
                _regression_gate_to_dict(
                    self.regression_gate
                )
                if self.regression_gate is not None
                else None
            ),
            "validation": (
                validation_summary_to_dict(
                    self.validation
                )
                if self.validation is not None
                else None
            ),
            "validation_results": (
                [
                    validation_result_to_dict(result)
                    for result in self.validation_results
                ]
                if self.validation_results is not None
                else None
            ),
            "validation_gate": (
                gate_decision_to_dict(
                    self.validation_gate
                )
                if self.validation_gate is not None
                else None
            ),
            "release_gate": self.release_gate.model_dump(
                mode="json"
            ),
            "release_allowed": self.release_allowed,
            "release_blocked": self.release_blocked,
        }


class SecurityPipeline:
    """Coordinate correlation, risk, policy, validation and release."""

    def __init__(
        self,
        *,
        correlation_engine: CorrelationEngine,
        risk_engine: RiskEngine,
        policy_engine: PolicyEngine,
        release_gate_engine: ReleaseGateEngine,
        regression_engine: RegressionEngine | None = None,
        validation_engine: ValidationEngine | None = None,
    ) -> None:
        self.correlation_engine = correlation_engine
        self.risk_engine = risk_engine
        self.policy_engine = policy_engine
        self.release_gate_engine = release_gate_engine
        self.regression_engine = regression_engine
        self.validation_engine = validation_engine

    def run(
        self,
        findings: list[Finding],
        *,
        validation_requests: list[ValidationRequest] | None = None,
        run_regression: bool = False,
    ) -> SecurityPipelineResult:
        """Run the complete security verification pipeline."""
        correlated_findings = self._correlate(findings)

        risk = self.risk_engine.evaluate(
            correlated_findings
        )

        policy = self.policy_engine.evaluate(
            correlated_findings,
            risk,
        )

        validation_summary: ValidationSummary | None = None
        validation_results: list[ValidationResult] | None = None
        validation_gate: ValidationGateDecision | None = None

        if validation_requests is not None:
            if self.validation_engine is None:
                raise RuntimeError(
                    "Validation requests were supplied, but no "
                    "ValidationEngine is configured."
                )

            validation_service = ValidationService(
                self.validation_engine
            )

            validation_summary = validation_service.validate_many(
                validation_requests
            )

            validation_results = validation_summary.results

            validation_gate = evaluate_validation_run(
                ValidationRun(
                    summary=validation_summary
                )
            )

        regression: RegressionSuiteResult | None = None
        regression_gate: RegressionGateDecision | None = None

        if run_regression:
            if self.regression_engine is None:
                raise RuntimeError(
                    "Regression execution was requested, but no "
                    "RegressionEngine is configured."
                )

            regression = self.regression_engine.run(
                correlated_findings
            )

            regression_gate = self.regression_engine.evaluate_gate(
                regression
            )

        release_gate = self._evaluate_release_gate(
            findings=correlated_findings,
            risk=risk,
            policy=policy,
            regression_gate=regression_gate,
            validation_gate=validation_gate,
        )

        return SecurityPipelineResult(
            findings=correlated_findings,
            risk=risk,
            policy=policy,
            regression=regression,
            regression_gate=regression_gate,
            release_gate=release_gate,
            validation=validation_summary,
            validation_gate=validation_gate,
            validation_results=validation_results,
        )

    def _correlate(
        self,
        findings: list[Finding],
    ) -> list[Finding]:
        """Correlate related findings."""
        result = self.correlation_engine.correlate(
            findings
        )

        if hasattr(result, "findings"):
            return result.findings

        return result

    def _evaluate_release_gate(
        self,
        *,
        findings: list[Finding],
        risk: RiskAssessment,
        policy: PolicyDecision,
        regression_gate: RegressionGateDecision | None,
        validation_gate: ValidationGateDecision | None,
    ) -> ReleaseGateDecision:
        """Evaluate the final release decision."""
        return self.release_gate_engine.evaluate(
            findings=findings,
            risk=risk,
            policy=policy,
            regression_gate=regression_gate,
            validation_gate=validation_gate,
        )


def _regression_gate_to_dict(
    decision: RegressionGateDecision,
) -> dict[str, Any]:
    """Serialize a regression-gate decision."""
    return {
        "allowed": decision.allowed,
        "blocked": decision.blocked,
        "status": decision.status,
        "reason": decision.reason,
        "failed_tests": list(
            decision.failed_tests
        ),
        "errored_tests": list(
            decision.errored_tests
        ),
        "skipped_tests": list(
            decision.skipped_tests
        ),
        "failures": list(
            decision.failures
        ),
    }
```
