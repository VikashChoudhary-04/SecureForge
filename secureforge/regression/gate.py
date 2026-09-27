"""Release-gate helpers for SecureForge regression testing."""

from **future** import annotations

from dataclasses import dataclass
from typing import Any

from .assessment import RegressionAssessment
from .models import RegressionStatus

@dataclass(frozen=True)
class RegressionGateDecision:
"""Decision produced from regression test results."""

```
allowed: bool
status: str
reason: str
failed_tests: tuple[str, ...]
errored_tests: tuple[str, ...]
skipped_tests: tuple[str, ...]

@property
def blocked(self) -> bool:
    """Return whether regressions block the release."""
    return not self.allowed

@property
def failures(self) -> tuple[str, ...]:
    """Return failed and errored regression identifiers."""
    return (
        self.failed_tests
        + self.errored_tests
    )

def to_dict(self) -> dict[str, Any]:
    """Serialize the regression gate decision."""
    return {
        "allowed": self.allowed,
        "blocked": self.blocked,
        "status": self.status,
        "reason": self.reason,
        "failed_tests": list(
            self.failed_tests
        ),
        "errored_tests": list(
            self.errored_tests
        ),
        "skipped_tests": list(
            self.skipped_tests
        ),
        "failures": list(
            self.failures
        ),
    }
```

def evaluate_regression_gate(
assessment: RegressionAssessment,
) -> RegressionGateDecision:
"""Evaluate whether regression results permit release."""
if assessment.failed > 0:
return RegressionGateDecision(
allowed=False,
status=RegressionStatus.FAILED.value,
reason=(
"One or more security regression tests failed."
),
failed_tests=assessment.failed_tests,
errored_tests=assessment.errored_tests,
skipped_tests=assessment.skipped_tests,
)

```
if assessment.errors > 0:
    return RegressionGateDecision(
        allowed=False,
        status=RegressionStatus.ERROR.value,
        reason=(
            "One or more security regression tests "
            "could not be executed."
        ),
        failed_tests=assessment.failed_tests,
        errored_tests=assessment.errored_tests,
        skipped_tests=assessment.skipped_tests,
    )

if assessment.status == RegressionStatus.SKIPPED:
    return RegressionGateDecision(
        allowed=True,
        status=RegressionStatus.SKIPPED.value,
        reason=(
            "Regression testing was skipped; "
            "no regression failure was observed."
        ),
        failed_tests=assessment.failed_tests,
        errored_tests=assessment.errored_tests,
        skipped_tests=assessment.skipped_tests,
    )

return RegressionGateDecision(
    allowed=True,
    status=RegressionStatus.PASSED.value,
    reason=(
        "All executed security regression tests passed."
    ),
    failed_tests=assessment.failed_tests,
    errored_tests=assessment.errored_tests,
    skipped_tests=assessment.skipped_tests,
)
```
