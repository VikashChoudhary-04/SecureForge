"""End-to-end security verification pipeline for SecureForge."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from secureforge.core.correlation import CorrelationEngine
from secureforge.core.findings import Finding
from secureforge.core.policy import PolicyEngine
from secureforge.core.risk import RiskEngine
from secureforge.core.scan.models import ScanExecution
from secureforge.core.release_gate import ReleaseGateEngine
from secureforge.regression.gate import RegressionGateDecision
from secureforge.validation.engine import ValidationEngine
from secureforge.validation.gate import ValidationGateDecision
from secureforge.validation.service import ValidationService


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

    @property
    def pipeline(self) -> "SecurityPipelineResult":
        return self

    @property
    def risk(self) -> Any | None:
        """Legacy alias for the aggregate risk section."""
        if not self.risk_assessments:
            return None
        return self.risk_assessments

    @property
    def policy(self) -> Any | None:
        """Legacy alias for the policy decision."""
        return self.policy_decision

    @property
    def release_gate(self) -> Any | None:
        """Legacy alias for the release decision."""
        return self.release_decision

    @property
    def validation(self) -> Any | None:
        """Legacy validation summary alias."""
        if self.validation_results is None:
            return None
        try:
            from secureforge.validation.service import ValidationService
            return ValidationService().summarize(self.validation_results)
        except Exception:
            return self.validation_results

    @property
    def execution(self) -> ScanExecution:
        application = (
            self.findings[0].application
            if self.findings
            else "securecommerce"
        )
        return ScanExecution(
            scan_id="pipeline-result",
            profile="standard",
            application=application,
            version="1.0.0",
            started_at="",
            completed_at="",
            target="unknown",
        )

    @property
    def release_blocked(self) -> bool:
        decision = self.release_decision
        if decision is None:
            return False
        if hasattr(decision, "release_allowed"):
            return not bool(decision.release_allowed)
        if hasattr(decision, "allowed"):
            return not bool(decision.allowed)
        if hasattr(decision, "decision"):
            value = getattr(decision, "decision")
            return getattr(value, "value", value) == "block"
        return False

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible compatibility representation."""
        def dump(value: Any) -> Any:
            if value is None:
                return None
            if hasattr(value, "model_dump"):
                return value.model_dump(mode="json")
            if isinstance(value, list):
                return [dump(item) for item in value]
            if isinstance(value, dict):
                return {key: dump(item) for key, item in value.items()}
            return value

        return {
            "findings": dump(self.findings),
            "correlated_findings": dump(self.correlated_findings),
            "risk": dump(self.risk),
            "policy": dump(self.policy),
            "release_gate": dump(self.release_gate),
            "validation": dump(self.validation),
            "validation_results": dump(self.validation_results),
            "validation_gate": dump(self.validation_gate),
            "regression_gate": dump(self.regression_gate),
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "release_blocked": self.release_blocked,
        }


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
        validation_engine: ValidationEngine | None = None,
    ) -> None:
        self.correlation_engine = correlation_engine or CorrelationEngine()
        self.risk_engine = risk_engine or RiskEngine()
        self.policy_engine = policy_engine or PolicyEngine()
        self.release_gate_engine = (
            release_gate_engine or ReleaseGateEngine()
        )
        if validation_service is None and validation_engine is None:
            validation_service = ValidationService()
        self.validation_service = validation_service
        self.validation_engine = validation_engine

    def run(
        self,
        findings: list[Finding],
        *,
        validation_requests: list[Any] | None = None,
        run_regression: bool = False,
    ) -> SecurityPipelineResult:
        result = SecurityPipelineResult(findings=list(findings))

        try:
            correlated = self._correlate(findings)
            result.correlated_findings = correlated
            result.risk_assessments = self._assess_risk(correlated)
            result.policy_decision = self._evaluate_policy(
                result.risk_assessments
            )

            if validation_requests:
                self._run_validation(
                    result,
                    validation_requests,
                )

            if run_regression:
                self._run_regression(result)

            result.release_decision = self._evaluate_release_gate(
                result
            )
        except Exception as exc:
            result.errors.append(
                f"Security pipeline failed: {exc}"
            )

        return result

    def _correlate(self, findings: list[Finding]) -> list[Finding]:
        if not findings:
            return []
        if hasattr(self.correlation_engine, "correlate"):
            correlated = self.correlation_engine.correlate(findings)
            return findings if correlated is None else list(correlated)
        return findings

    def _assess_risk(self, findings: list[Finding]) -> list[Any]:
        if not findings:
            return []
        if hasattr(self.risk_engine, "assess_many"):
            return list(self.risk_engine.assess_many(findings))
        if hasattr(self.risk_engine, "evaluate_many"):
            return list(self.risk_engine.evaluate_many(findings))
        if hasattr(self.risk_engine, "assess"):
            return [self.risk_engine.assess(finding) for finding in findings]
        if hasattr(self.risk_engine, "evaluate"):
            return [self.risk_engine.evaluate(finding) for finding in findings]
        return []

    def _evaluate_policy(self, risk_assessments: list[Any]) -> Any | None:
        if hasattr(self.policy_engine, "evaluate_many"):
            return self.policy_engine.evaluate_many(risk_assessments)
        if hasattr(self.policy_engine, "evaluate"):
            return self.policy_engine.evaluate(risk_assessments)
        return None

    def _run_validation(
        self,
        result: SecurityPipelineResult,
        validation_requests: list[Any],
    ) -> None:
        try:
            if self.validation_engine is not None:
                service_result = self.validation_engine.validate_many(
                    validation_requests
                )
            elif self.validation_service is not None:
                service_result = self.validation_service.validate_many(
                    validation_requests
                )
            else:
                service_result = []

            if isinstance(service_result, tuple):
                validation_results, validation_gate = service_result
                result.validation_results = list(validation_results)
                result.validation_gate = validation_gate
            else:
                result.validation_results = list(
                    getattr(service_result, "results", service_result)
                )
        except Exception as exc:
            result.errors.append(f"Validation failed: {exc}")

    def _run_regression(self, result: SecurityPipelineResult) -> None:
        regression_gate = None
        try:
            from secureforge.regression.gate import RegressionGate

            gate = RegressionGate()
            if hasattr(gate, "evaluate"):
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
        if not hasattr(self.release_gate_engine, "evaluate"):
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


__all__ = [
    "SecurityPipeline",
    "SecurityPipelineResult",
]
