"""Release-gate orchestration for SecureForge."""

from **future** import annotations

from secureforge.core.policy.models import PolicyDecision
from secureforge.core.risk.models import RiskAssessment

from .evaluator import ReleaseGateEvaluator
from .models import ReleaseGateDecision
from .regression import RegressionGateResult

class ReleaseGateEngine:
"""Combine security policy and regression results into a release decision."""

```
def __init__(
    self,
    evaluator: ReleaseGateEvaluator | None = None,
) -> None:
    self.evaluator = (
        evaluator
        if evaluator is not None
        else ReleaseGateEvaluator()
    )

def evaluate(
    self,
    *,
    risk: RiskAssessment,
    policy: PolicyDecision,
    regression: RegressionGateResult | None = None,
) -> ReleaseGateDecision:
    """Evaluate whether the release is allowed."""
    decision = self.evaluator.evaluate(
        risk=risk,
        policy=policy,
    )

    if regression is None:
        return decision

    if regression.blocked:
        return ReleaseGateDecision(
            status=decision.status.BLOCKED,
            reason=(
                f"{decision.reason} "
                f"Regression gate blocked the release: "
                f"{regression.reason}"
            ),
            release_allowed=False,
        )

    return decision
```
