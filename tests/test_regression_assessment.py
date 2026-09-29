"""Tests for SecureForge regression assessment."""

from __future__ import annotations

from secureforge.regression import (
RegressionResult,
RegressionStatus,
RegressionSuiteResult,
assess_regression_result,
)

def build_result(
*,
suite_status: RegressionStatus,
results: list[RegressionResult],
) -> RegressionSuiteResult:
"""Build a representative regression suite result."""
return RegressionSuiteResult(
suite_id="securecommerce-regression",
name="SecureCommerce Regression Suite",
status=suite_status,
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

def test_assessment_marks_successful_suite_as_not_blocked():
"""A fully passing suite should not block release."""
result = build_result(
suite_status=RegressionStatus.PASSED,
results=[
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


assessment = assess_regression_result(
    result
)

assert assessment.suite_id == (
    "securecommerce-regression"
)
assert assessment.status == (
    RegressionStatus.PASSED
)
assert assessment.total == 2
assert assessment.passed == 2
assert assessment.failed == 0
assert assessment.errors == 0
assert assessment.skipped == 0
assert assessment.failed_tests == ()
assert assessment.errored_tests == ()
assert assessment.skipped_tests == ()
assert assessment.release_blocked is False
assert assessment.successful is True
assert assessment.failure_ids == ()


def test_assessment_blocks_release_for_failed_tests():
"""A failed regression should block the release."""
result = build_result(
suite_status=RegressionStatus.FAILED,
results=[
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


assessment = assess_regression_result(
    result
)

assert assessment.status == (
    RegressionStatus.FAILED
)
assert assessment.total == 2
assert assessment.passed == 1
assert assessment.failed == 1
assert assessment.errors == 0
assert assessment.failed_tests == (
    "BOLA-001",
)
assert assessment.errored_tests == ()
assert assessment.release_blocked is True
assert assessment.successful is False
assert assessment.failure_ids == (
    "BOLA-001",
)


def test_assessment_blocks_release_for_errors():
"""A regression execution error should block the release."""
result = build_result(
suite_status=RegressionStatus.ERROR,
results=[
build_test_result(
"SECRET-001",
RegressionStatus.ERROR,
),
],
)


assessment = assess_regression_result(
    result
)

assert assessment.status == (
    RegressionStatus.ERROR
)
assert assessment.total == 1
assert assessment.passed == 0
assert assessment.failed == 0
assert assessment.errors == 1
assert assessment.failed_tests == ()
assert assessment.errored_tests == (
    "SECRET-001",
)
assert assessment.release_blocked is True
assert assessment.successful is False
assert assessment.failure_ids == (
    "SECRET-001",
)


def test_assessment_tracks_skipped_tests():
"""Skipped regressions should be reported separately."""
result = build_result(
suite_status=RegressionStatus.SKIPPED,
results=[
build_test_result(
"MISCONFIG-001",
RegressionStatus.SKIPPED,
),
],
)


assessment = assess_regression_result(
    result
)

assert assessment.status == (
    RegressionStatus.SKIPPED
)
assert assessment.total == 1
assert assessment.passed == 0
assert assessment.failed == 0
assert assessment.errors == 0
assert assessment.skipped == 1
assert assessment.skipped_tests == (
    "MISCONFIG-001",
)
assert assessment.release_blocked is False
assert assessment.successful is False


def test_assessment_handles_mixed_results():
"""Assessment should classify every regression status correctly."""
result = build_result(
suite_status=RegressionStatus.ERROR,
results=[
build_test_result(
"BOLA-001",
RegressionStatus.FAILED,
),
build_test_result(
"SQLI-001",
RegressionStatus.ERROR,
),
build_test_result(
"XSS-001",
RegressionStatus.PASSED,
),
build_test_result(
"SECRET-001",
RegressionStatus.SKIPPED,
),
],
)


assessment = assess_regression_result(
    result
)

assert assessment.total == 4
assert assessment.passed == 1
assert assessment.failed == 1
assert assessment.errors == 1
assert assessment.skipped == 1

assert assessment.failed_tests == (
    "BOLA-001",
)
assert assessment.errored_tests == (
    "SQLI-001",
)
assert assessment.skipped_tests == (
    "SECRET-001",
)
assert assessment.failure_ids == (
    "BOLA-001",
    "SQLI-001",
)
assert assessment.release_blocked is True
assert assessment.successful is False


def test_assessment_serializes_to_dictionary():
"""Assessment should provide report-friendly dictionary output."""
result = build_result(
suite_status=RegressionStatus.FAILED,
results=[
build_test_result(
"BOLA-001",
RegressionStatus.FAILED,
),
build_test_result(
"XSS-001",
RegressionStatus.PASSED,
),
],
)


assessment = assess_regression_result(
    result
)

data = assessment.to_dict()

assert data == {
    "suite_id": "securecommerce-regression",
    "suite_name": (
        "SecureCommerce Regression Suite"
    ),
    "status": "failed",
    "total": 2,
    "passed": 1,
    "failed": 1,
    "errors": 0,
    "skipped": 0,
    "failed_tests": [
        "BOLA-001",
    ],
    "errored_tests": [],
    "skipped_tests": [],
    "release_blocked": True,
}

