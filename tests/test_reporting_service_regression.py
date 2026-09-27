"""Tests for regression integration in SecurityReportService."""

from **future** import annotations

import json

from secureforge.regression import (
RegressionResult,
RegressionStatus,
RegressionSuiteResult,
)
from secureforge.reporting.models import (
ReleaseMetadata,
RemediationReport,
ScanMetadata,
)
from secureforge.reporting.service import (
ReportPaths,
SecurityReportService,
)

def build_regression_result() -> RegressionSuiteResult:
"""Build a representative regression result."""
return RegressionSuiteResult(
suite_id="securecommerce-regression",
name="SecureCommerce Regression Suite",
status=RegressionStatus.FAILED,
results=[
RegressionResult(
test_id="BOLA-001",
security_requirement="SF-AUTHZ-001",
status=RegressionStatus.FAILED,
expected="HTTP 403",
actual="HTTP 200",
message="Cross-user access remains possible.",
evidence={
"status_code": 200,
},
started_at=(
"2026-09-27T10:00:00+00:00"
),
completed_at=(
"2026-09-27T10:00:01+00:00"
),
duration_seconds=1.0,
),
],
started_at="2026-09-27T10:00:00+00:00",
completed_at="2026-09-27T10:00:01+00:00",
duration_seconds=1.0,
)

def test_generate_from_results_includes_regression(
sample_release: ReleaseMetadata,
sample_scan: ScanMetadata,
sample_findings,
sample_risk,
sample_policy,
sample_decision,
sample_remediation: RemediationReport,
tmp_path,
):
"""Service should generate reports containing regression results."""
service = SecurityReportService()

```
paths = ReportPaths(
    json_path=(
        tmp_path
        / "security-report.json"
    ),
    html_path=(
        tmp_path
        / "security-report.html"
    ),
)

result = service.generate_from_results(
    release=sample_release,
    scan=sample_scan,
    findings=sample_findings,
    risk=sample_risk,
    policy=sample_policy,
    decision=sample_decision,
    remediation=sample_remediation,
    regression=build_regression_result(),
    paths=paths,
)

assert result == paths
assert paths.json_path.is_file()
assert paths.html_path.is_file()

report_data = json.loads(
    paths.json_path.read_text(
        encoding="utf-8"
    )
)

assert report_data["regression"]["suite_id"] == (
    "securecommerce-regression"
)
assert report_data["regression"]["status"] == "failed"
assert report_data["regression"]["total"] == 1
assert report_data["regression"]["failed"] == 1
assert report_data["regression"]["tests"][0]["test_id"] == (
    "BOLA-001"
)

html = paths.html_path.read_text(
    encoding="utf-8"
)

assert "Regression Testing" in html
assert "SecureCommerce Regression Suite" in html
assert "BOLA-001" in html
assert "HTTP 403" in html
assert "HTTP 200" in html
```

def test_generate_without_regression_records_not_run(
sample_release: ReleaseMetadata,
sample_scan: ScanMetadata,
sample_findings,
sample_risk,
sample_policy,
sample_decision,
sample_remediation: RemediationReport,
tmp_path,
):
"""Service should explicitly report when regression was not run."""
service = SecurityReportService()

```
paths = ReportPaths(
    json_path=(
        tmp_path
        / "security-report.json"
    ),
    html_path=(
        tmp_path
        / "security-report.html"
    ),
)

service.generate_from_results(
    release=sample_release,
    scan=sample_scan,
    findings=sample_findings,
    risk=sample_risk,
    policy=sample_policy,
    decision=sample_decision,
    remediation=sample_remediation,
    paths=paths,
)

report_data = json.loads(
    paths.json_path.read_text(
        encoding="utf-8"
    )
)

assert report_data["regression"]["suite_id"] == (
    "not-run"
)
assert report_data["regression"]["status"] == (
    "skipped"
)
assert report_data["regression"]["total"] == 0

html = paths.html_path.read_text(
    encoding="utf-8"
)

assert "Regression Testing" in html
assert "No regression tests were executed." in html
```

def test_build_report_preserves_regression_without_writing(
sample_release: ReleaseMetadata,
sample_scan: ScanMetadata,
sample_findings,
sample_risk,
sample_policy,
sample_decision,
sample_remediation: RemediationReport,
):
"""Service should build an in-memory report with regression data."""
service = SecurityReportService()

```
report = service.build_report(
    release=sample_release,
    scan=sample_scan,
    findings=sample_findings,
    risk=sample_risk,
    policy=sample_policy,
    decision=sample_decision,
    remediation=sample_remediation,
    regression=build_regression_result(),
)

assert report.regression.suite_id == (
    "securecommerce-regression"
)
assert report.regression.status == "failed"
assert len(report.regression.tests) == 1
```
