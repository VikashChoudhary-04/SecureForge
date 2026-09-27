"""Tests for regression integration in the release-gate engine."""

from secureforge.core.release_gate.engine import (
ReleaseGateEngine,
)
from secureforge.core.release_gate.models import (
ReleaseGateStatus,
)
from secureforge.core.release_gate.regression import (
RegressionGateResult,
)

def test_release_gate_engine_blocks_on_regression_failure(
sample_risk,
sample_policy,
) -> None:
"""Block the release when the regression gate is blocked."""
regression = RegressionGateResult(
allowed=False,
blocked=True,
status="failed",
reason=(
"One or more security regression tests failed."
),
failures=("BOLA-001",),
skipped_tests=(),
)

```
engine = ReleaseGateEngine()

decision = engine.evaluate(
    risk=sample_risk,
    policy=sample_policy,
    regression=regression,
)

assert decision.status == ReleaseGateStatus.BLOCKED
assert decision.release_allowed is False
assert "Regression gate blocked the release" in (
    decision.reason
)
assert (
    "One or more security regression tests failed."
    in decision.reason
)
```

def test_release_gate_engine_preserves_decision_when_regression_passes(
sample_risk,
sample_policy,
) -> None:
"""Preserve the normal release-gate decision when regressions pass."""
regression = RegressionGateResult(
allowed=True,
blocked=False,
status="passed",
reason=(
"All executed security regression tests passed."
),
failures=(),
skipped_tests=(),
)

```
engine = ReleaseGateEngine()

decision = engine.evaluate(
    risk=sample_risk,
    policy=sample_policy,
    regression=regression,
)

assert decision.release_allowed is True
assert decision.status != ReleaseGateStatus.BLOCKED
```

def test_release_gate_engine_preserves_existing_behavior_without_regression(
sample_risk,
sample_policy,
) -> None:
"""Keep existing release-gate behavior when no regression result exists."""
engine = ReleaseGateEngine()

```
decision = engine.evaluate(
    risk=sample_risk,
    policy=sample_policy,
)

assert decision.release_allowed is True
assert decision.status != ReleaseGateStatus.BLOCKED
```
