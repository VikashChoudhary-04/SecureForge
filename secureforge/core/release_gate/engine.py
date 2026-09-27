"""Release-gate decision engine for SecureForge."""

from **future** import annotations

from secureforge.core.policy import PolicyDecision

from .models import (
ReleaseDecision,
ReleaseDecisionRecord,
ReleaseGateInput,
)

class ReleaseGateEngine:
"""Produce the final release decision from security evaluation results."""

```
_priority = {
    ReleaseDecision.PASS: 0,
    ReleaseDecision.REVIEW: 1,
    ReleaseDecision.BLOCK: 2,
}

def evaluate(
    self,
    gate_input: ReleaseGateInput,
) -> ReleaseDecisionRecord:
    """Evaluate release readiness."""
    decision = self._from_policy_decision(
        gate_input.policy_decision
    )

    reasons: list[str] = []

    if gate_input.blocking_findings:
        decision = self._higher_decision(
            decision,
            ReleaseDecision.BLOCK,
        )

        reasons.append(
            "One or more findings triggered release-blocking policy conditions."
        )

    if gate_input.failed_regressions:
        decision = self._higher_decision(
            decision,
            ReleaseDecision.BLOCK,
        )

        reasons.append(
            "One or more security regression tests failed."
        )

    if gate_input.tool_errors:
        decision = self._higher_decision(
            decision,
            ReleaseDecision.REVIEW,
        )

        reasons.append(
            "One or more security integrations reported execution errors."
        )

    if gate_input.review_findings:
        decision = self._higher_decision(
            decision,
            ReleaseDecision.REVIEW,
        )

        reasons.append(
            "One or more findings require security review."
        )

    if gate_input.exceptions_applied:
        reasons.append(
            "One or more configured policy exceptions were applied."
        )

    if decision == ReleaseDecision.PASS and not reasons:
        reasons.append(
            "No configured release-blocking or review conditions were triggered."
        )

    return ReleaseDecisionRecord(
        application=gate_input.application,
        version=gate_input.version,
        commit_sha=gate_input.commit_sha,
        decision=decision,
        reasons=reasons,
        blocking_findings=gate_input.blocking_findings,
        review_findings=gate_input.review_findings,
        failed_regressions=gate_input.failed_regressions,
        tool_errors=gate_input.tool_errors,
        exceptions_applied=gate_input.exceptions_applied,
        metadata=gate_input.metadata,
    )

@staticmethod
def _from_policy_decision(
    decision: PolicyDecision,
) -> ReleaseDecision:
    """Convert a policy decision to a release decision."""
    return ReleaseDecision(decision.value)

def _higher_decision(
    self,
    current: ReleaseDecision,
    candidate: ReleaseDecision,
) -> ReleaseDecision:
    """Return the higher-priority release decision."""
    if self._priority[candidate] > self._priority[current]:
        return candidate

    return current
```
