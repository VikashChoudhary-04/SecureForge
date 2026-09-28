"""Regression-gate integration helpers for SecureForge."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from secureforge.regression import RegressionGateDecision

@dataclass(frozen=True)
class RegressionGateResult:
"""Release-gate compatible representation of regression results."""

```
allowed: bool
blocked: bool
status: str
reason: str
failures: tuple[str, ...]
skipped_tests: tuple[str, ...]

@property
def has_failures(self) -> bool:
    """Return whether regression results contain failures."""
    return bool(self.failures)

def to_dict(self) -> dict[str, Any]:
    """Serialize the regression-gate result."""
    return {
        "allowed": self.allowed,
        "blocked": self.blocked,
        "status": self.status,
        "reason": self.reason,
        "failures": list(self.failures),
        "skipped_tests": list(
            self.skipped_tests
        ),
    }
```

def build_regression_gate_result(
decision: RegressionGateDecision,
) -> RegressionGateResult:
"""Convert a regression decision into release-gate input."""
return RegressionGateResult(
allowed=decision.allowed,
blocked=decision.blocked,
status=decision.status,
reason=decision.reason,
failures=decision.failures,
skipped_tests=decision.skipped_tests,
)
