"""End-to-end security verification pipeline for SecureForge."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from secureforge.core.correlation import CorrelationEngine
from secureforge.core.findings import Finding
from secureforge.core.policy import PolicyConfig, PolicyEngine
from secureforge.core.risk import RiskEngine, RiskLevel
from secureforge.core.release_gate import ReleaseGateEngine
from secureforge.regression.gate import RegressionGateDecision
from secureforge.validation.engine import ValidationEngine
from secureforge.validation.gate import ValidationGateDecision, evaluate_validation_run
from secureforge.validation.models import ValidationSummary
from secureforge.validation.runner import ValidationRun
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
    regression: Any | None = None
    regression_gate: RegressionGateDecision | None = None
    validation_results: list[Any] | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def __init__(
        self,
        findings: list[Finding] | None = None,
        correlated_findings: list[Finding] | None = None,
        risk_assessments: list[Any] | None = None,
        policy_decision: Any | None = None,
        release_decision: Any | None = None,
        validation_gate: ValidationGateDecision | None = None,
        regression: Any | None = None,
        regression_gate: RegressionGateDecision | None = None,
        validation_results: list[Any] | None = None,
        errors: list[str] | None = None,
        warnings: list[str] | None = None,
        *,
        risk: Any | None = None,
        policy: Any | None = None,
        release_gate: Any | None = None,
    ) -> None:
        self.findings = list(findings or [])
        self.correlated_findings = list(
            correlated_findings
            if correlated_findings is not None
            else self.findings
        )
        self.risk_assessments = (
            list(risk_assessments)
            if risk_assessments is not None
            else ([risk] if risk is not None else [])
        )
        self.policy_decision = (
            policy_decision
            if policy_decision is not None
            else policy
        )
        self.release_decision = (
            release_decision
            if release_decision is not None
            else release_gate
        )
        self.validation_gate = validation_gate
        self.regression = regression
        self.regression_gate = regression_gate
        self.validation_results = validation_results
        self.errors = list(errors or [])
        self.warnings = list(warnings or [])

    @property
    def pipeline(self) -> "SecurityPipelineResult":
        return self

    @property
    def risk(self) -> Any:
        """Return one aggregate risk assessment for compatibility."""
        if len(self.risk_assessments) == 1:
            assessment = self.risk_assessments[0]
            if getattr(assessment, "finding_count", None) == len(self.findings):
                return assessment

        from secureforge.core.risk.models import RiskAssessment

        if not self.risk_assessments:
            return RiskAssessment(
                finding_id="aggregate",
                base_severity=RiskLevel.INFO,
                contextual_risk=RiskLevel.INFO,
                risk_score=0.0,
                factors=[],
                explanation="No findings were available for risk assessment.",
                evaluated_at="",
                finding_count=len(self.findings),
            )

        highest = max(
            self.risk_assessments,
            key=lambda item: float(
                getattr(item, "risk_score", getattr(item, "score", 0.0))
            ),
        )
        risk_level = getattr(
            highest,
            "contextual_risk",
            getattr(highest, "highest_severity", RiskLevel.INFO),
        )

        return RiskAssessment(
            finding_id="aggregate",
            base_severity=risk_level,
            contextual_risk=risk_level,
            risk_score=max(
                float(
                    getattr(item, "risk_score", getattr(item, "score", 0.0))
                )
                for item in self.risk_assessments
            ),
            factors=[
                factor
                for item in self.risk_assessments
                for factor in (getattr(item, "factors", []) or [])
            ],
            explanation="Aggregate contextual risk for the scan.",
            evaluated_at="",
            finding_count=len(self.findings),
        )

    @property
    def policy(self) -> Any | None:
        return self.policy_decision

    @property
    def release_gate(self) -> Any | None:
        return self.release_decision

    @property
    def validation(self) -> ValidationSummary | None:
        if self.validation_results is None:
            return None
        return ValidationService.summarize(self.validation_results)

    @property
    def release_allowed(self) -> bool:
        decision = self.release_decision
        if decision is None:
            return False
        return bool(
            getattr(
                decision,
                "release_allowed",
                getattr(decision, "allowed", False),
            )
        )

    @property
    def release_blocked(self) -> bool:
        return not self.release_allowed

    @property
    def execution(self):
        from secureforge.core.scan.models import ScanExecution

        application = (
            getattr(self.findings[0], "application", "securecommerce")
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
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible pipeline representation."""

        def dump(value: Any) -> Any:
            if value is None:
                return None
            if hasattr(value, "model_dump"):
                return value.model_dump(mode="json")
            if hasattr(value, "to_dict"):
                return value.to_dict()
            if isinstance(value, list):
                return [dump(item) for item in value]
            if isinstance(value, tuple):
                return [dump(item) for item in value]
            if isinstance(value, dict):
                return {
                    key: dump(item)
                    for key, item in value.items()
                }
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
            "regression": dump(self.regression),
            "regression_gate": dump(self.regression_gate),
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "release_allowed": self.release_allowed,
            "release_blocked": self.release_blocked,
        }


class SecurityPipeline:
    """Coordinate correlation, risk, policy, validation and release gating."""

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
        self.correlation_engine = (
            correlation_engine or CorrelationEngine()
        )
        self.risk_engine = risk_engine or RiskEngine()
        self.policy_engine = policy_engine or PolicyEngine()
        self.release_gate_engine = (
            release_gate_engine or ReleaseGateEngine()
        )

        if validation_service is None and validation_engine is None:
            validation_service = ValidationService()

        self.validation_service = validation_service
        self.validation_engine = validation_engine

    def evaluate(
        self,
        findings: Iterable[Finding],
        *,
        tool_errors: list[str] | None = None,
        policy: PolicyConfig | None = None,
        regression: Any | None = None,
        regression_result: Any | None = None,
        regression_gate: RegressionGateDecision | None = None,
        validation_requests: list[Any] | None = None,
        **_: Any,
    ) -> SecurityPipelineResult:
        """Evaluate findings through the complete security pipeline."""
        effective_regression = (
            regression
            if regression is not None
            else regression_result
        )

        return self._evaluate(
            list(findings),
            tool_errors=tool_errors or [],
            policy=policy,
            regression=effective_regression,
            regression_gate=regression_gate,
            validation_requests=validation_requests,
        )

    def run(
        self,
        findings: list[Finding],
        *,
        validation_requests: list[Any] | None = None,
        run_regression: bool = False,
        regression: Any | None = None,
        regression_result: Any | None = None,
        regression_gate: RegressionGateDecision | None = None,
        tool_errors: list[str] | None = None,
        policy: PolicyConfig | None = None,
        **_: Any,
    ) -> SecurityPipelineResult:
        """Run the compatibility pipeline entry point."""
        effective_regression = (
            regression
            if regression is not None
            else regression_result
        )

        return self._evaluate(
            list(findings),
            tool_errors=tool_errors or [],
            policy=policy,
            regression=effective_regression,
            regression_gate=regression_gate,
            validation_requests=validation_requests,
            run_regression=run_regression,
        )

    def _evaluate(
        self,
        findings: list[Finding],
        *,
        tool_errors: list[str],
        policy: PolicyConfig | None,
        regression: Any | None,
        regression_gate: RegressionGateDecision | None,
        validation_requests: list[Any] | None,
        run_regression: bool = False,
    ) -> SecurityPipelineResult:
        result = SecurityPipelineResult(findings=findings)

        try:
            result.correlated_findings = self._correlate(findings)
            result.risk_assessments = self._assess_risk(
                result.correlated_findings
            )

            effective_policy = policy or self._default_policy()

            evaluation = self.policy_engine.evaluate(
                result.correlated_findings,
                result.risk_assessments,
                effective_policy,
                tool_errors=len(tool_errors),
                failed_regressions=self._regression_failures(regression),
            )

            result.policy_decision = getattr(
                evaluation,
                "decision",
                evaluation,
            )

            if tool_errors:
                violations = getattr(
                    result.policy_decision,
                    "violations",
                    None,
                )
                if isinstance(violations, list):
                    violations.extend(tool_errors)

            if validation_requests:
                self._run_validation(
                    result,
                    validation_requests,
                )

            result.regression = regression

            if regression_gate is not None:
                result.regression_gate = regression_gate
            elif run_regression and regression is not None:
                result.regression_gate = (
                    self._build_regression_gate(regression)
                )

            result.release_decision = (
                self.release_gate_engine.evaluate(
                    findings=result.correlated_findings,
                    risk=result.risk,
                    policy=result.policy,
                    regression_gate=result.regression_gate,
                    validation_gate=result.validation_gate,
                )
            )

        except Exception as exc:
            result.errors.append(
                f"Security pipeline failed: {exc}"
            )

        return result

    @staticmethod
    def _default_policy() -> PolicyConfig:
        from secureforge.core.policy.models import (
            PolicyAction,
            PolicyRule,
        )

        return PolicyConfig(
            policy_id="secureforge-default",
            version="1.0",
            rules=[
                PolicyRule(
                    rule_id="BLOCK-CRITICAL",
                    name="Block critical",
                    description="Critical findings block release.",
                    severity="critical",
                    action=PolicyAction.BLOCK,
                ),
                PolicyRule(
                    rule_id="BLOCK-HIGH",
                    name="Block high",
                    description="High findings block release.",
                    severity="high",
                    action=PolicyAction.BLOCK,
                ),
                PolicyRule(
                    rule_id="REVIEW-MEDIUM",
                    name="Review medium",
                    description="Medium findings require review.",
                    severity="medium",
                    action=PolicyAction.REVIEW,
                ),
                PolicyRule(
                    rule_id="PASS-LOW",
                    name="Pass low",
                    description="Low findings are permitted.",
                    severity="low",
                    action=PolicyAction.PASS,
                ),
                PolicyRule(
                    rule_id="PASS-INFO",
                    name="Pass info",
                    description="Informational findings are permitted.",
                    severity="info",
                    action=PolicyAction.PASS,
                ),
            ],
        )

    def _correlate(
        self,
        findings: list[Finding],
    ) -> list[Finding]:
        if not findings:
            return []

        correlated = self.correlation_engine.correlate(
            findings
        )

        # The policy/risk stages operate on normalized findings.
        # Correlation groups are retained by the finding model.
        if correlated is None:
            return findings

        if correlated and hasattr(
            correlated[0],
            "source_finding_ids",
        ):
            return findings

        return list(correlated)

    def _assess_risk(
        self,
        findings: list[Finding],
    ) -> list[Any]:
        assessments: list[Any] = []

        for finding in findings:
            assessments.append(
                self.risk_engine.evaluate(finding)
            )

        return assessments

    def _run_validation(
        self,
        result: SecurityPipelineResult,
        requests: list[Any],
    ) -> None:
        if self.validation_engine is not None:
            raw = self.validation_engine.validate_many(
                requests
            )
        elif self.validation_service is not None:
            raw = self.validation_service.validate_many(
                requests
            )
        else:
            raw = []

        if isinstance(raw, ValidationSummary):
            result.validation_results = list(
                raw.results
            )
        elif isinstance(raw, tuple) and len(raw) == 2:
            result.validation_results = list(
                raw[0]
            )
            result.validation_gate = raw[1]
        else:
            result.validation_results = list(
                getattr(raw, "results", raw)
            )

        if result.validation_gate is None:
            summary = ValidationService.summarize(
                result.validation_results
            )
            result.validation_gate = evaluate_validation_run(
                ValidationRun(
                    summary=summary
                )
            )

    @staticmethod
    def _regression_failures(
        regression: Any | None,
    ) -> list[str]:
        if regression is None:
            return []

        failures: list[str] = []

        for item in getattr(
            regression,
            "results",
            [],
        ):
            status = getattr(
                getattr(item, "status", None),
                "value",
                getattr(item, "status", None),
            )

            if status in {"failed", "error"}:
                failures.append(
                    getattr(
                        item,
                        "test_id",
                        "unknown",
                    )
                )

        return failures

    @staticmethod
    def _build_regression_gate(
        regression: Any,
    ) -> RegressionGateDecision:
        from secureforge.regression.assessment import (
            RegressionAssessment,
        )
        from secureforge.regression.gate import (
            evaluate_regression_gate,
        )

        assessment = RegressionAssessment.from_suite(
            regression
        )

        return evaluate_regression_gate(
            assessment
        )

    def summarize(
        self,
        result: SecurityPipelineResult,
    ) -> dict[str, Any]:
        """Return a compact pipeline summary."""
        return {
            "finding_count": len(result.findings),
            "risk": result.risk.model_dump(mode="json"),
            "policy": (
                result.policy.model_dump(mode="json")
                if hasattr(
                    result.policy,
                    "model_dump",
                )
                else result.policy
            ),
            "release_gate": (
                result.release_gate.model_dump(mode="json")
                if hasattr(
                    result.release_gate,
                    "model_dump",
                )
                else result.release_gate
            ),
        }


__all__ = [
    "SecurityPipeline",
    "SecurityPipelineResult",
]
