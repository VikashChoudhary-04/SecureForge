"""End-to-end security verification pipeline for SecureForge."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from secureforge.core.correlation import CorrelationEngine
from secureforge.core.findings import Finding
from secureforge.core.policy import PolicyEngine
from secureforge.core.risk import RiskEngine

from secureforge.core.release_gate import (
    ReleaseDecision,
    ReleaseGateEngine,
)

from secureforge.regression.gate import (
    RegressionGateDecision,
)

from secureforge.validation.gate import (
    ValidationGateDecision,
)

from secureforge.validation.service import (
    ValidationService,
)


@dataclass
class SecurityPipelineResult:
    """Aggregated result produced by the security pipeline."""

    findings: list[Finding] = field(default_factory=list)
    correlated_findings: list[Finding] = field(default_factory=list)
    risk_assessments: list[Any] = field(default_factory=list)
    policy_decision: Any | None = None
    release_decision: Any | None = None
    validation_gate: ValidationGateDecision | None = None
    regression_gate: RegressionGateDecision | None = None
    validation_results: list[Any] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class SecurityPipeline:
    """Coordinate normalization, correlation, risk, policy, and validation."""

    def __init__(
        self,
        *,
        correlation_engine: CorrelationEngine | None = None,
        risk_engine: RiskEngine | None = None,
        policy_engine: PolicyEngine | None = None,
        release_gate_engine: ReleaseGateEngine | None = None,
        validation_service: ValidationService | None = None,
    ) -> None:
        self.correlation_engine = (
            correlation_engine
            or CorrelationEngine()
        )
        self.risk_engine = (
            risk_engine
            or RiskEngine()
        )
        self.policy_engine = (
            policy_engine
            or PolicyEngine()
        )
        self.release_gate_engine = (
            release_gate_engine
            or ReleaseGateEngine()
        )
        self.validation_service = (
            validation_service
            or ValidationService()
        )

    def run(
        self,
        findings: list[Finding],
        *,
        validation_requests: list[Any] | None = None,
        run_regression: bool = False,
    ) -> SecurityPipelineResult:
        """Run the complete security verification pipeline."""
        result = SecurityPipelineResult(
            findings=list(findings),
        )

        try:
            correlated = self._correlate(
                findings
            )
            result.correlated_findings = correlated

            result.risk_assessments = self._assess_risk(
                correlated
            )

            result.policy_decision = self._evaluate_policy(
                result.risk_assessments
            )

            if validation_requests:
                self._run_validation(
                    result,
                    validation_requests,
                )

            if run_regression:
                self._run_regression(
                    result
                )

            result.release_decision = (
                self._evaluate_release_gate(
                    result
                )
            )

        except Exception as exc:
            result.errors.append(
                f"Security pipeline failed: {exc}"
            )

        return result

    def _correlate(
        self,
        findings: list[Finding],
    ) -> list[Finding]:
        """Correlate duplicate or related findings."""
        if not findings:
            return []

        engine = self.correlation_engine

        if hasattr(engine, "correlate"):
            correlated = engine.correlate(
                findings
            )

            if correlated is None:
                return findings

            return list(correlated)

        return findings

    def _assess_risk(
        self,
        findings: list[Finding],
    ) -> list[Any]:
        """Calculate contextual risk assessments."""
        if not findings:
            return []

        engine = self.risk_engine

        if hasattr(engine, "assess_many"):
            return list(
                engine.assess_many(
                    findings
                )
            )

        if hasattr(engine, "assess"):
            assessments = []

            for finding in findings:
                assessments.append(
                    engine.assess(
                        finding
                    )
                )

            return assessments

        return []

    def _evaluate_policy(
        self,
        risk_assessments: list[Any],
    ) -> Any | None:
        """Evaluate configured security policy."""
        engine = self.policy_engine

        if hasattr(engine, "evaluate_many"):
            return engine.evaluate_many(
                risk_assessments
            )

        if hasattr(engine, "evaluate"):
            return engine.evaluate(
                risk_assessments
            )

        return None

    def _run_validation(
        self,
        result: SecurityPipelineResult,
        validation_requests: list[Any],
    ) -> None:
        """Execute requested vulnerability validation."""
        try:
            service_result = self.validation_service.validate_many(
                validation_requests
            )

            if isinstance(service_result, tuple):
                validation_results, validation_gate = (
                    service_result
                )

                result.validation_results = list(
                    validation_results
                )
                result.validation_gate = validation_gate
            else:
                result.validation_results = list(
                    service_result
                )

        except Exception as exc:
            result.errors.append(
                f"Validation failed: {exc}"
            )

    def _run_regression(
        self,
        result: SecurityPipelineResult,
    ) -> None:
        """Run regression controls when available."""
        regression_gate = None

        try:
            from secureforge.regression.gate import (
                RegressionGate,
            )

            gate = RegressionGate()

            if hasattr(
                gate,
                "evaluate",
            ):
                regression_gate = gate.evaluate(
                    result.correlated_findings
                )

        except (ImportError, AttributeError):
            result.warnings.append(
                "Regression gate is not configured."
            )

        except Exception as exc:
            result.errors.append(
                f"Regression evaluation failed: {exc}"
            )

        result.regression_gate = regression_gate

    def _evaluate_release_gate(
        self,
        result: SecurityPipelineResult,
    ) -> Any | None:
        """Produce the final release decision."""
        if not hasattr(
            self.release_gate_engine,
            "evaluate",
        ):
            return None

        try:
            return self.release_gate_engine.evaluate(
                findings=result.correlated_findings,
                risk=result.risk_assessments,
                policy=result.policy_decision,
                regression_gate=result.regression_gate,
                validation_gate=result.validation_gate,
            )

        except Exception as exc:
            result.errors.append(
                f"Release-gate evaluation failed: {exc}"
            )
            return None
