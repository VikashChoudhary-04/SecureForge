"""Regression reporting adapters for SecureForge."""

from **future** import annotations

from .models import (
RegressionReport,
RegressionTestReport,
)
from secureforge.regression import (
RegressionSuiteResult,
)

def build_regression_report(
result: RegressionSuiteResult,
) -> RegressionReport:
"""Convert a regression suite result into a security report section."""
tests = [
RegressionTestReport(
test_id=regression_result.test_id,
status=regression_result.status.value,
expected=regression_result.expected,
actual=regression_result.actual,
message=regression_result.message,
evidence=regression_result.evidence,
)
for regression_result in result.results
]

```
return RegressionReport(
    suite_id=result.suite_id,
    suite_name=result.name,
    status=result.status.value,
    total=result.total,
    passed=result.passed,
    failed=result.failed,
    errors=result.errors,
    skipped=result.skipped,
    tests=tests,
    started_at=result.started_at,
    completed_at=result.completed_at,
    duration_seconds=result.duration_seconds,
)
```
