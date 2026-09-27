"""Tests for regression-gate integration in the reporting service."""

from pathlib import Path

from secureforge.regression import (
RegressionGateDecision,
)
from secureforge.reporting import (
ReportPaths,
RegressionGateReport,
SecurityReportService,
)

def test_service_build_report_includes_regression_gate(
sample_release,
sample_scan,
sample_findings,
sample_risk,
sample_policy,
sample_decision,
) -> None:
"""Include regression gate data when building a report."""
regression_gate = RegressionGateDecision(
allowed=False,
status="failed",
reason=(
"One or more security regression tests failed."
),
failed_tests=("BOLA-001",),
errored_tests=("AUTHZ-001",),
skipped_tests=("OPTIONAL-001",),
)

```
service = SecurityReportService()

report = service.build_report(
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
assert report.regression_gate.failed_tests == [
    "BOLA-001"
]
assert report.regression_gate.errored_tests == [
    "AUTHZ-001"
]
assert report.regression_gate.skipped_tests == [
    "OPTIONAL-001"
]
```

def test_service_generate_from_results_accepts_regression_gate(
sample_release,
sample_scan,
sample_findings,
sample_risk,
sample_policy,
sample_decision,
tmp_path: Path,
) -> None:
"""Pass regression gate data through report generation."""
regression_gate = RegressionGateDecision(
allowed=True,
status="passed",
reason=(
"All executed security regression tests passed."
),
failed_tests=(),
errored_tests=(),
skipped_tests=(),
)

```
service = SecurityReportService()

paths = ReportPaths(
    json_path=tmp_path / "security-report.json",
    html_path=tmp_path / "security-report.html",
)

generated_paths = service.generate_from_results(
    release=sample_release,
    scan=sample_scan,
    findings=sample_findings,
    risk=sample_risk,
    policy=sample_policy,
    decision=sample_decision,
    paths=paths,
    regression_gate=regression_gate,
)

assert generated_paths == paths
assert paths.json_path.exists()
assert paths.html_path.exists()

json_content = paths.json_path.read_text(
    encoding="utf-8"
)

assert '"regression_gate"' in json_content
assert '"allowed": true' in json_content
assert '"status": "passed"' in json_content

html_content = paths.html_path.read_text(
    encoding="utf-8"
)

assert "Regression Gate" in html_content
assert "passed" in html_content
```
