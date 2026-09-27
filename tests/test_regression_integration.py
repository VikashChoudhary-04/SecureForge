"""Tests for SecureForge regression gate integration."""

from **future** import annotations

from secureforge.regression import (
RegressionResult,
RegressionStatus,
RegressionSuiteResult,
build_regression_gate_input,
build_regression_gate_input_from_assessment,
assess_regression_result,
)

def build_result(
status: RegressionStatus,
results: list[RegressionResult],
) -> RegressionSuiteResult:
"""Build a representative regression suite result."""
return RegressionSuiteResult(
suite_id="securecommerce-regression",
name="SecureCommerce Regression Suite",
status=status,
results=results,
started_at="2026-09-27T10:00:00+00:00",
completed_at="2026-09-27T10:00:01+00:00",
duration_seconds=1.0,
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

def test_build_gate_input_from_suite_result():
"""Suite results should become release-gate input."""
result = build_result(
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
build_test_result(
"SECRET-001",
RegressionStatus.ERROR,
),
build_test_result(
"XSS-001",
RegressionStatus.SKIPPED,
),
],
)

```
gate_input = build_regression_gate_input(
    result
)

assert gate_input.suite_id == (
    "securecommerce-regression"
)
assert gate_input.suite_name == (
    "SecureCommerce Regression Suite"
)
assert gate_input.status == "failed"
assert gate_input.failed_tests == (
    "BOLA-001",
)
assert gate_input.errored_tests == (
    "SECRET-001",
)
assert gate_input.skipped_tests == (
    "XSS-001",
)
assert gate_input.failures == (
    "BOLA-001",
    "SECRET-001",
)
assert gate_input.has_failures is True
assert gate_input.release_blocked is True
```

def test_build_gate_input_from_passing_suite():
"""A passing suite should produce a non-blocking gate input."""
result = build_result(
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
gate_input = build_regression_gate_input(
    result
)

assert gate_input.status == "passed"
assert gate_input.failed_tests == ()
assert gate_input.errored_tests == ()
assert gate_input.failures == ()
assert gate_input.has_failures is False
assert gate_input.release_blocked is False
```

def test_build_gate_input_from_assessment():
"""Existing assessments should convert consistently."""
result = build_result(
RegressionStatus.ERROR,
[
build_test_result(
"AUTHZ-001",
RegressionStatus.ERROR,
),
],
)

```
assessment = assess_regression_result(
    result
)

gate_input = (
    build_regression_gate_input_from_assessment(
        assessment
    )
)

assert gate_input.suite_id == assessment.suite_id
assert gate_input.suite_name == assessment.suite_name
assert gate_input.status == assessment.status.value
assert gate_input.failed_tests == (
    assessment.failed_tests
)
assert gate_input.errored_tests == (
    assessment.errored_tests
)
assert gate_input.skipped_tests == (
    assessment.skipped_tests
)
assert gate_input.release_blocked is True
```

def test_gate_input_serializes_for_reporting():
"""Gate input should produce report-friendly data."""
result = build_result(
RegressionStatus.FAILED,
[
build_test_result(
"BOLA-001",
RegressionStatus.FAILED,
),
],
)

```
gate_input = build_regression_gate_input(
    result
)

data = gate_input.to_dict()

assert data == {
    "suite_id": "securecommerce-regression",
    "suite_name": (
        "SecureCommerce Regression Suite"
    ),
    "status": "failed",
    "failed_tests": [
        "BOLA-001",
    ],
    "errored_tests": [],
    "skipped_tests": [],
    "failures": [
        "BOLA-001",
    ],
    "release_blocked": True,
}
```
