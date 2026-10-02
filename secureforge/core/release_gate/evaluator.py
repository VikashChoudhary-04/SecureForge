"""Release decision evaluation rules for SecureForge."""

from __future__ import annotations

from .models import ReleaseDecision, ReleaseGateInput


class ReleaseDecisionEvaluator:
    """Evaluate release-gate conditions using explicit precedence rules."""

    _priority = {
        ReleaseDecision.PASS: 0,
        ReleaseDecision.REVIEW: 1,
        ReleaseDecision.BLOCK: 2,
    }

    def evaluate(self, gate_input: ReleaseGateInput) -> tuple[ReleaseDecision, list[str]]:
        decision = self.from_policy_decision(gate_input.policy_decision)
        reasons: list[str] = []

        if gate_input.blocking_findings:
            decision = self.higher_decision(decision, ReleaseDecision.BLOCK)
            reasons.append("One or more findings triggered release-blocking policy conditions.")
        if gate_input.failed_regressions:
            decision = self.higher_decision(decision, ReleaseDecision.BLOCK)
            reasons.append("One or more security regression tests failed.")
        if gate_input.tool_errors:
            decision = self.higher_decision(decision, ReleaseDecision.REVIEW)
            reasons.append("One or more security integrations reported execution errors.")
        if gate_input.review_findings:
            decision = self.higher_decision(decision, ReleaseDecision.REVIEW)
            reasons.append("One or more findings require security review.")
        if gate_input.exceptions_applied:
            reasons.append("One or more configured policy exceptions were applied.")
        if decision == ReleaseDecision.PASS and not reasons:
            reasons.append("No configured release-blocking or review conditions were triggered.")
        return decision, reasons

    @staticmethod
    def from_policy_decision(decision) -> ReleaseDecision:
        if isinstance(decision, ReleaseDecision):
            return decision
        raw = getattr(decision, "action", decision)
        raw = getattr(raw, "value", raw)
        return ReleaseDecision(str(raw).lower())

    @classmethod
    def higher_decision(cls, current: ReleaseDecision, candidate: ReleaseDecision) -> ReleaseDecision:
        return candidate if cls._priority[candidate] > cls._priority[current] else current


class ReleaseGateEvaluator(ReleaseDecisionEvaluator):
    """Public compatibility evaluator retained for the release-gate API."""


__all__ = ["ReleaseDecisionEvaluator", "ReleaseGateEvaluator"]
