"""Release-gate engine for SecureForge."""

from __future__ import annotations

from typing import Any

from .evaluator import ReleaseDecisionEvaluator
from .models import ReleaseDecision, ReleaseGateDecision, ReleaseGateInput


class ReleaseGateEngine:
    """Evaluate release-gate conditions through the production evaluator."""

    def __init__(self, evaluator: Any | None = None) -> None:
        self.evaluator = evaluator or ReleaseDecisionEvaluator()

    def evaluate(
        self,
        gate_input: ReleaseGateInput | None = None,
        *,
        findings: list[Any] | None = None,
        risk: Any | None = None,
        policy: Any | None = None,
        regression_gate: Any | None = None,
        validation_gate: Any | None = None,
        regression: Any | None = None,
        application: str = "",
        version: str = "",
        commit_sha: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ReleaseGateDecision:
        if gate_input is None:
            gate_input = self._build_input(
                findings=findings,
                risk=risk,
                policy=policy,
                regression_gate=regression_gate,
                validation_gate=validation_gate,
                regression=regression,
                application=application,
                version=version,
                commit_sha=commit_sha,
                metadata=metadata,
            )

            if validation_gate is not None:
                validation_status = getattr(validation_gate, "status", "")
                validation_status = getattr(validation_status, "value", validation_status)
                if str(validation_status).lower() == "passed":
                    return ReleaseGateDecision(
                        application=gate_input.application,
                        version=gate_input.version,
                        commit_sha=gate_input.commit_sha,
                        decision=ReleaseDecision.PASS,
                        reasons=[getattr(validation_gate, "reason", "Security validation passed.")],
                        metadata=dict(gate_input.metadata),
                    )

            regression_value = regression_gate if regression_gate is not None else regression
            if regression_value is not None and bool(getattr(regression_value, "blocked", False)):
                failures = (
                    getattr(regression_value, "failures", None)
                    or getattr(regression_value, "failed_tests", None)
                    or []
                )
                reason = "Regression gate blocked the release"
                if failures:
                    reason += ": " + ", ".join(str(item) for item in failures)
                return ReleaseGateDecision(
                    application=gate_input.application,
                    version=gate_input.version,
                    commit_sha=gate_input.commit_sha,
                    decision=ReleaseDecision.BLOCK,
                    reasons=[reason],
                    failed_regressions=[str(item) for item in failures],
                    metadata=dict(gate_input.metadata),
                )

        decision, reasons = self.evaluator.evaluate(gate_input)
        return ReleaseGateDecision(
            application=gate_input.application,
            version=gate_input.version,
            commit_sha=gate_input.commit_sha,
            decision=decision,
            reasons=reasons,
            blocking_findings=list(gate_input.blocking_findings),
            review_findings=list(gate_input.review_findings),
            failed_regressions=list(gate_input.failed_regressions),
            tool_errors=list(gate_input.tool_errors),
            exceptions_applied=list(gate_input.exceptions_applied),
            metadata=dict(gate_input.metadata),
        )

    @staticmethod
    def _build_input(
        *,
        findings,
        risk,
        policy,
        regression_gate,
        validation_gate,
        regression,
        application,
        version,
        commit_sha,
        metadata,
    ) -> ReleaseGateInput:
        blocking, review, failed_regressions, tool_errors = [], [], [], []

        for finding in findings or []:
            finding_id = str(getattr(finding, "finding_id", finding))
            severity = getattr(getattr(finding, "severity", None), "value", getattr(finding, "severity", None))
            if bool(getattr(finding, "blocked", False)) or severity == "critical":
                blocking.append(finding_id)

        if risk is not None and bool(getattr(risk, "blocked", False)):
            blocking.append("risk-threshold")

        if policy is None:
            policy_decision = ReleaseDecision.PASS
        else:
            action = getattr(policy, "action", policy)
            action = getattr(action, "value", action)
            policy_decision = ReleaseDecision(str(action).lower())

        if validation_gate is not None:
            status = getattr(validation_gate, "status", "")
            status = getattr(status, "value", status)
            if bool(getattr(validation_gate, "blocked", False)) or str(status).lower() in {"blocked", "failed"}:
                blocking.append("validation")
            elif str(status).lower() in {"review", "error", "inconclusive"}:
                review.append("validation")

        regression_value = regression_gate if regression_gate is not None else regression
        if regression_value is not None:
            status = getattr(regression_value, "status", "")
            status = getattr(status, "value", status)
            if bool(getattr(regression_value, "blocked", False)) or str(status).lower() in {"failed", "blocked"}:
                failures = getattr(regression_value, "failed_tests", None) or getattr(regression_value, "failures", None) or []
                failed_regressions.extend(str(item) for item in failures)
                if not failed_regressions:
                    failed_regressions.append("regression")
            elif str(status).lower() in {"review", "error"}:
                tool_errors.append("regression")

        return ReleaseGateInput(
            application=application or "SecureCommerce",
            version=version or "1.0.0",
            commit_sha=commit_sha,
            policy_decision=policy_decision,
            blocking_findings=blocking,
            review_findings=review,
            failed_regressions=failed_regressions,
            tool_errors=tool_errors,
            metadata=dict(metadata or {}),
        )


__all__ = ["ReleaseGateEngine"]
