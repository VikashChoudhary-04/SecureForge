"""Tests for the SecureForge regression release gate."""

from **future** import annotations

from secureforge.regression import (
RegressionResult,
RegressionStatus,
RegressionSuiteResult,
assess_regression_result,
evaluate_regression_gate,
)

def build_test_result(
test_id: str,
status: RegressionStatus,
) -> RegressionResult:
"""Build a representative regression result."""
return RegressionResult(
test_id=test_id,
security_requirement="SF-TEST-001",
status=status,
expected="Secure behavior",
actual=(
"Secure behavior"
if status == RegressionStatus.PASSED
else "Insecure behavior"
),
message=f"{test_id} result.",
started_at="2026-09-27T10:00:00+00:00",
completed_at="2026-09-27T10:00:01+00:00",
duration_seconds=1.0,
)

def build_assessment(
status: RegressionStatus,
results: list[RegressionResult],
):
"""Build a regression assessment."""
suite_result = RegressionSuiteResult(
suite_id="securecommerce-regression",
name="SecureCommerce Regression Suite",
status=status,
results=results,
started_at="2026-09-27T10:00:00+00:00",
completed_at="2026-09-27T10:00:01+00:00",
duration_seconds=1.0,
)

```
return assess_regression_result(
    suite_result
)
```

def test_gate_allows_passing_regressions():
"""All passing regressions should allow release."""
assessment = build_assessment(
RegressionStatus.PASSED,
[
build_test_result(
"BOLA-001",
RegressionStatus.PASSED,
),
build_test_result(
"SQLI-001",
RegressionStatus.PASSED,
),
],
)

```
decision = evaluate_regression_gate(
    assessment
)

assert decision.allowed is True
assert decision.blocked is False
assert decision.status == "passed"
assert decision.reason == (
    "All executed security regression tests passed."
)
assert decision.failed_tests == ()
assert decision.errored_tests == ()
assert decision.failures == ()
```

def test_gate_blocks_failed_regressions():
"""A failed regression should block release."""
assessment = build_assessment(
RegressionStatus.FAILED,
[
build_test_result(
"BOLA-001",
RegressionStatus.FAILED,
),
build_test_result(
"SQLI-001",
RegressionStatus.PASSED,
),
],
)

```
decision = evaluate_regression_gate(
    assessment
)

assert decision.allowed is False
assert decision.blocked is True
assert decision.status == "failed"
assert decision.reason == (
    "One or more security regression tests failed."
)
assert decision.failed_tests == (
    "BOLA-001",
)
assert decision.errored_tests == ()
assert decision.failures == (
    "BOLA-001",
)
```

def test_gate_blocks_regression_errors():
"""A regression execution error should block release."""
assessment = build_assessment(
RegressionStatus.ERROR,
[
build_test_result(
"SECRET-001",
RegressionStatus.ERROR,
),
],
)

```
decision = evaluate_regression_gate(
    assessment
)

assert decision.allowed is False
assert decision.blocked is True
assert decision.status == "error"
assert decision.reason == (
    "One or more security regression tests "
    "could not be executed."
)
assert decision.failed_tests == ()
assert decision.errored_tests == (
    "SECRET-001",
)
assert decision.failures == (
    "SECRET-001",
)
```

def test_gate_allows_skipped_regressions():
"""Skipped regression testing should remain explicitly visible."""
assessment = build_assessment(
RegressionStatus.SKIPPED,
[
build_test_result(
"MISCONFIG-001",
RegressionStatus.SKIPPED,
),
],
)

```
decision = evaluate_regression_gate(
    assessment
)

assert decision.allowed is True
assert decision.blocked is False
assert decision.status == "skipped"
assert decision.reason == (
    "Regression testing was skipped; "
    "no regression failure was observed."
)
assert decision.skipped_tests == (
    "MISCONFIG-001",
)
```

def test_failed_regression_takes_precedence_over_error():
"""A failed regression should be reported before an execution error."""
assessment = build_assessment(
RegressionStatus.ERROR,
[
build_test_result(
"BOLA-001",
RegressionStatus.FAILED,
),
build_test_result(
"SECRET-001",
RegressionStatus.ERROR,
),
],
)

```
decision = evaluate_regression_gate(
    assessment
)

assert decision.allowed is False
assert decision.status == "failed"
assert decision.failed_tests == (
    "BOLA-001",
)
assert decision.errored_tests == (
    "SECRET-001",
)
```

def test_gate_decision_serializes_to_dictionary():
"""Gate decisions should be report-friendly."""
assessment = build_assessment(
RegressionStatus.FAILED,
[
build_test_result(
"BOLA-001",
RegressionStatus.FAILED,
),
],
)

```
decision = evaluate_regression_gate(
    assessment
)

data = decision.to_dict()

assert data == {
    "allowed": False,
    "blocked": True,
    "status": "failed",
    "reason": (
        "One or more security regression tests failed."
    ),
    "failed_tests": [
        "BOLA-001",
    ],
    "errored_tests": [],
    "skipped_tests": [],
    "failures": [
        "BOLA-001",
    ],
}
```
