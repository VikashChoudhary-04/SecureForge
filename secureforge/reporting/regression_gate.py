"""Regression gate reporting adapters for SecureForge."""

from **future** import annotations

from secureforge.regression import RegressionGateDecision

from .models import RegressionGateReport

def build_regression_gate_report(
decision: RegressionGateDecision,
) -> RegressionGateReport:
"""Convert a regression gate decision into report data."""
return RegressionGateReport(
allowed=decision.allowed,
blocked=decision.blocked,
status=decision.status,
reason=decision.reason,
failed_tests=list(
decision.failed_tests
),
errored_tests=list(
decision.errored_tests
),
skipped_tests=list(
decision.skipped_tests
),
failures=list(
decision.failures
),
)
