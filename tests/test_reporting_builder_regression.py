"""Tests for regression integration in SecurityReportBuilder."""

from **future** import annotations

from secureforge.core.findings.models import Finding
from secureforge.core.policy.models import PolicyDecision
from secureforge.core.release_gate.models import ReleaseGateDecision
from secureforge.core.risk.models import RiskAssessment
from secureforge.regression import (
RegressionResult,
RegressionStatus,
RegressionSuiteResult,
)
from secureforge.reporting.builder import SecurityReportBuilder
from secureforge.reporting.models import (
ReleaseMetadata,
RemediationReport,
ScanMetadata,
)

def build_regression_result() -> RegressionSuiteResult:
"""Build a representative regression suite result."""
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
message="Cross-user order access remains possible.",
evidence={
"status_code": 200,
"expected_status_code": 403,
},
started_at=(
"2026-09-27T10:00:00+00:00"
),
completed_at=(
"2026-09-27T10:00:01+00:00"
),
duration_seconds=1.0,
),
RegressionResult(
test_id="SQLI-001",
security_requirement="SF-INPUT-001",
status=RegressionStatus.PASSED,
expected="Rejected",
actual="Rejected",
message="SQL injection input was safely rejected.",
evidence={
"status_code": 400,
},
started_at=(
"2026-09-27T10:00:01+00:00"
),
completed_at=(
"2026-09-27T10:00:02+00:00"
),
duration_seconds=1.0,
),
],
started_at="2026-09-27T10:00:00+00:00",
completed_at="2026-09-27T10:00:02+00:00",
duration_seconds=2.0,
)

def test_security_report_builder_includes_regression_results(
sample_release: ReleaseMetadata,
sample_scan: ScanMetadata,
sample_findings: list[Finding],
sample_risk: RiskAssessment,
sample_policy: PolicyDecision,
sample_decision: ReleaseGateDecision,
sample_remediation: RemediationReport,
):
"""Builder should include regression results in the final report."""
builder = SecurityReportBuilder()

```
report = builder.build(
    release=sample_release,
    scan=sample_scan,
    findings=sample_findings,
    risk=sample_risk,
    policy=sample_policy,
    decision=sample_decision,
    remediation=sample_remediation,
    regression=build_regression_result(),
)

assert report.regression is not None
assert report.regression.suite_id == (
    "securecommerce-regression"
)
assert report.regression.suite_name == (
    "SecureCommerce Regression Suite"
)
assert report.regression.status == "failed"
assert report.regression.total == 2
assert report.regression.passed == 1
assert report.regression.failed == 1
assert report.regression.errors == 0
assert report.regression.skipped == 0
```

def test_security_report_builder_preserves_regression_tests(
sample_release: ReleaseMetadata,
sample_scan: ScanMetadata,
sample_findings: list[Finding],
sample_risk: RiskAssessment,
sample_policy: PolicyDecision,
sample_decision: ReleaseGateDecision,
sample_remediation: RemediationReport,
):
"""Builder should preserve individual regression results."""
builder = SecurityReportBuilder()

```
report = builder.build(
    release=sample_release,
    scan=sample_scan,
    findings=sample_findings,
    risk=sample_risk,
    policy=sample_policy,
    decision=sample_decision,
    remediation=sample_remediation,
    regression=build_regression_result(),
)

assert len(report.regression.tests) == 2

bola = report.regression.tests[0]
sqli = report.regression.tests[1]

assert bola.test_id == "BOLA-001"
assert bola.status == "failed"
assert bola.expected == "HTTP 403"
assert bola.actual == "HTTP 200"
assert bola.evidence["status_code"] == 200

assert sqli.test_id == "SQLI-001"
assert sqli.status == "passed"
assert sqli.actual == "Rejected"
```

def test_security_report_builder_defaults_regression_to_skipped(
sample_release: ReleaseMetadata,
sample_scan: ScanMetadata,
sample_findings: list[Finding],
sample_risk: RiskAssessment,
sample_policy: PolicyDecision,
sample_decision: ReleaseGateDecision,
sample_remediation: RemediationReport,
):
"""Reports without regression execution should remain explicit."""
builder = SecurityReportBuilder()

```
report = builder.build(
    release=sample_release,
    scan=sample_scan,
    findings=sample_findings,
    risk=sample_risk,
    policy=sample_policy,
    decision=sample_decision,
    remediation=sample_remediation,
)

assert report.regression is not None
assert report.regression.suite_id == "not-run"
assert report.regression.status == "skipped"
assert report.regression.total == 0
assert report.regression.tests == []
```
