"""Release-gate decision engine for SecureForge."""

from **future** import annotations

from secureforge.core.policy import PolicyDecision

from .evaluator import ReleaseDecisionEvaluator
from .models import (
ReleaseDecisionRecord,
ReleaseGateInput,
)

class ReleaseGateEngine:
"""Produce the final release decision from security evaluation results."""

```
def __init__(
    self,
    evaluator: ReleaseDecisionEvaluator | None = None,
) -> None:
    self.evaluator = evaluator or ReleaseDecisionEvaluator()

def evaluate(
    self,
    gate_input: ReleaseGateInput,
) -> ReleaseDecisionRecord:
    """Evaluate release readiness."""
    decision, reasons = self.evaluator.evaluate(
        gate_input
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
```
