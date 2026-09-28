"""Integration helpers for SecureForge regression results."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .assessment import (
RegressionAssessment,
assess_regression_result,
)
from .models import RegressionSuiteResult

@dataclass(frozen=True)
class RegressionGateInput:
"""Release-gate input derived from regression testing."""

```
suite_id: str
suite_name: str
status: str
failed_tests: tuple[str, ...]
errored_tests: tuple[str, ...]
skipped_tests: tuple[str, ...]
release_blocked: bool

@property
def failures(self) -> tuple[str, ...]:
    """Return failed and errored regression identifiers."""
    return (
        self.failed_tests
        + self.errored_tests
    )

@property
def has_failures(self) -> bool:
    """Return whether any regression requires release blocking."""
    return self.release_blocked

def to_dict(self) -> dict[str, Any]:
    """Serialize the gate input."""
    return {
        "suite_id": self.suite_id,
        "suite_name": self.suite_name,
        "status": self.status,
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
        "release_blocked": self.release_blocked,
    }
```

def build_regression_gate_input(
result: RegressionSuiteResult,
) -> RegressionGateInput:
"""Convert regression results into release-gate input."""
assessment = assess_regression_result(
result
)

```
return RegressionGateInput(
    suite_id=assessment.suite_id,
    suite_name=assessment.suite_name,
    status=assessment.status.value,
    failed_tests=assessment.failed_tests,
    errored_tests=assessment.errored_tests,
    skipped_tests=assessment.skipped_tests,
    release_blocked=assessment.release_blocked,
)
```

def build_regression_gate_input_from_assessment(
assessment: RegressionAssessment,
) -> RegressionGateInput:
"""Build gate input from an existing regression assessment."""
return RegressionGateInput(
suite_id=assessment.suite_id,
suite_name=assessment.suite_name,
status=assessment.status.value,
failed_tests=assessment.failed_tests,
errored_tests=assessment.errored_tests,
skipped_tests=assessment.skipped_tests,
release_blocked=assessment.release_blocked,
)
