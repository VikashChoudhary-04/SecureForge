"""Tests for regression-gate integration in the security report builder."""

from secureforge.regression import (
RegressionGateDecision,
)
from secureforge.reporting import (
RegressionGateReport,
SecurityReportBuilder,
)

def test_builder_includes_regression_gate_report(
sample_release,
sample_scan,
sample_findings,
sample_risk,
sample_policy,
sample_decision,
) -> None:
"""Include regression gate data in the complete security report."""
regression_gate = RegressionGateDecision(
allowed=False,
status="failed",
reason=(
"One or more security regression tests failed."
),
failed_tests=("BOLA-001",),
errored_tests=(),
skipped_tests=(),
)

```
builder = SecurityReportBuilder()

report = builder.build(
    release=sample_release,
    scan=sample_scan,
    findings=sample_findings,
    risk=sample_risk,
    policy=sample_policy,
    decision=sample_decision,
    regression_gate=regression_gate,
)

assert isinstance(
    report.regression_gate,
    RegressionGateReport,
)

assert report.regression_gate.allowed is False
assert report.regression_gate.blocked is True
assert report.regression_gate.status == "failed"
assert report.regression_gate.reason == (
    "One or more security regression tests failed."
)
assert report.regression_gate.failed_tests == [
    "BOLA-001"
]
assert report.regression_gate.errored_tests == []
assert report.regression_gate.skipped_tests == []
assert report.regression_gate.failures == [
    "BOLA-001"
]
```

def test_builder_allows_report_without_regression_gate(
sample_release,
sample_scan,
sample_findings,
sample_risk,
sample_policy,
sample_decision,
) -> None:
"""Keep regression-gate reporting optional for compatibility."""
builder = SecurityReportBuilder()

```
report = builder.build(
    release=sample_release,
    scan=sample_scan,
    findings=sample_findings,
    risk=sample_risk,
    policy=sample_policy,
    decision=sample_decision,
)

assert report.regression_gate is None
```
