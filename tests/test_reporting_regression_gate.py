"""Tests for regression gate reporting adapters."""

from secureforge.regression import (
RegressionGateDecision,
)
from secureforge.reporting import (
RegressionGateReport,
build_regression_gate_report,
)

def test_build_regression_gate_report_from_allowed_decision() -> None:
"""Build a report section from an allowed regression decision."""
decision = RegressionGateDecision(
allowed=True,
status="passed",
reason=(
"All executed security regression tests passed."
),
failed_tests=(),
errored_tests=(),
skipped_tests=("OPTIONAL-001",),
)

report = build_regression_gate_report(
    decision
)

assert isinstance(
    report,
    RegressionGateReport,
)
assert report.allowed is True
assert report.blocked is False
assert report.status == "passed"
assert report.reason == (
    "All executed security regression tests passed."
)
assert report.failed_tests == []
assert report.errored_tests == []
assert report.skipped_tests == [
    "OPTIONAL-001"
]
assert report.failures == []

def test_build_regression_gate_report_from_failed_decision() -> None:
"""Build a report section from a failed regression decision."""
decision = RegressionGateDecision(
allowed=False,
status="failed",
reason=(
"One or more security regression tests failed."
),
failed_tests=(
"BOLA-001",
"SQLI-001",
),
errored_tests=(
"AUTHZ-001",
),
skipped_tests=(
"OPTIONAL-001",
),
)

report = build_regression_gate_report(
    decision
)

assert report.allowed is False
assert report.blocked is True
assert report.status == "failed"
assert report.failed_tests == [
    "BOLA-001",
    "SQLI-001",
]
assert report.errored_tests == [
    "AUTHZ-001"
]
assert report.skipped_tests == [
    "OPTIONAL-001"
]
assert report.failures == [
    "BOLA-001",
    "SQLI-001",
    "AUTHZ-001",
]

def test_regression_gate_report_serializes_correctly() -> None:
"""Verify the regression gate report exposes report-ready data."""
decision = RegressionGateDecision(
allowed=False,
status="error",
reason=(
"One or more security regression tests "
"could not be executed."
),
failed_tests=(),
errored_tests=("BOLA-001",),
skipped_tests=(),
)

report = build_regression_gate_report(
    decision
)

serialized = report.model_dump()

assert serialized["allowed"] is False
assert serialized["blocked"] is True
assert serialized["status"] == "error"
assert serialized["errored_tests"] == [
    "BOLA-001"
]
assert serialized["failures"] == [
    "BOLA-001"
]
