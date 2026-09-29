"""Tests for regression reporting adapters."""

from __future__ import annotations

from secureforge.regression import (
RegressionResult,
RegressionStatus,
RegressionSuiteResult,
)
from secureforge.reporting.regression import (
build_regression_report,
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
evidence={
"source": "securecommerce",
"synthetic": True,
},
started_at="2026-09-27T10:00:00+00:00",
completed_at="2026-09-27T10:00:01+00:00",
duration_seconds=1.0,
)

def test_build_regression_report_preserves_suite_metadata():
"""Regression report should preserve suite-level information."""
result = RegressionSuiteResult(
suite_id="securecommerce-regression",
name="SecureCommerce Regression Suite",
status=RegressionStatus.FAILED,
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
started_at="2026-09-27T10:00:00+00:00",
completed_at="2026-09-27T10:00:02+00:00",
duration_seconds=2.0,
)

report = build_regression_report(
    result
)

assert report.suite_id == (
    "securecommerce-regression"
)
assert report.suite_name == (
    "SecureCommerce Regression Suite"
)
assert report.status == "failed"
assert report.total == 2
assert report.passed == 1
assert report.failed == 1
assert report.errors == 0
assert report.skipped == 0
assert report.started_at == (
    "2026-09-27T10:00:00+00:00"
)
assert report.completed_at == (
    "2026-09-27T10:00:02+00:00"
)
assert report.duration_seconds == 2.0

def test_build_regression_report_preserves_test_results():
"""Every regression result should become a report test."""
result = RegressionSuiteResult(
suite_id="securecommerce-regression",
name="SecureCommerce Regression Suite",
status=RegressionStatus.ERROR,
results=[
build_test_result(
"BOLA-001",
RegressionStatus.FAILED,
),
build_test_result(
"SQLI-001",
RegressionStatus.PASSED,
),
build_test_result(
"XSS-001",
RegressionStatus.ERROR,
),
build_test_result(
"SECRET-001",
RegressionStatus.SKIPPED,
),
],
started_at="2026-09-27T10:00:00+00:00",
completed_at="2026-09-27T10:00:04+00:00",
duration_seconds=4.0,
)

report = build_regression_report(
    result
)

assert len(report.tests) == 4

first = report.tests[0]

assert first.test_id == "BOLA-001"
assert first.status == "failed"
assert first.expected == "Secure behavior"
assert first.actual == "Insecure behavior"
assert first.message == "BOLA-001 result."
assert first.evidence == {
    "source": "securecommerce",
    "synthetic": True,
}

assert report.tests[1].test_id == "SQLI-001"
assert report.tests[1].status == "passed"

assert report.tests[2].test_id == "XSS-001"
assert report.tests[2].status == "error"

assert report.tests[3].test_id == "SECRET-001"
assert report.tests[3].status == "skipped"

def test_build_regression_report_handles_empty_suite():
"""An empty regression suite should still produce a valid report."""
result = RegressionSuiteResult(
suite_id="empty-suite",
name="Empty Suite",
status=RegressionStatus.SKIPPED,
results=[],
started_at="2026-09-27T10:00:00+00:00",
completed_at="2026-09-27T10:00:00+00:00",
duration_seconds=0.0,
)

report = build_regression_report(
    result
)

assert report.suite_id == "empty-suite"
assert report.suite_name == "Empty Suite"
assert report.status == "skipped"
assert report.total == 0
assert report.passed == 0
assert report.failed == 0
assert report.errors == 0
assert report.skipped == 0
assert report.tests == []

def test_build_regression_report_preserves_evidence():
"""Regression evidence should remain available in the report."""
result = RegressionSuiteResult(
suite_id="evidence-suite",
name="Evidence Suite",
status=RegressionStatus.PASSED,
results=[
RegressionResult(
test_id="SECRET-001",
security_requirement="SF-SECRET-001",
status=RegressionStatus.PASSED,
expected="No active secret detected.",
actual="No active hardcoded secret detected.",
message="Source secret regression passed.",
evidence={
"matches": [],
"values_redacted": True,
},
started_at=(
"2026-09-27T10:00:00+00:00"
),
completed_at=(
"2026-09-27T10:00:01+00:00"
),
duration_seconds=1.0,
)
],
started_at="2026-09-27T10:00:00+00:00",
completed_at="2026-09-27T10:00:01+00:00",
duration_seconds=1.0,
)

report = build_regression_report(
    result
)

assert report.tests[0].evidence == {
    "matches": [],
    "values_redacted": True,
}
