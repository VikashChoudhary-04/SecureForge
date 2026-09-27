"""Tests for SecureForge reporting models."""

from **future** import annotations

from datetime import datetime, timezone

from secureforge.reporting import (
DecisionReport,
PolicyReport,
RegressionReport,
RegressionTestReport,
ReleaseMetadata,
RemediationReport,
ReportFinding,
RiskReport,
ScanMetadata,
SecurityReport,
)

def test_release_metadata_defaults_timestamp():
"""Release metadata should create a UTC timestamp automatically."""
release = ReleaseMetadata(
release_id="release-001",
application="SecureCommerce",
version="0.1.0",
environment="lab",
profile="standard",
)

```
assert release.release_id == "release-001"
assert release.application == "SecureCommerce"
assert release.version == "0.1.0"
assert release.environment == "lab"
assert release.profile == "standard"
assert release.timestamp.tzinfo == timezone.utc
```

def test_scan_metadata_preserves_execution_information():
"""Scan metadata should preserve scan execution details."""
started = datetime(
2026,
9,
27,
8,
0,
tzinfo=timezone.utc,
)

```
completed = datetime(
    2026,
    9,
    27,
    8,
    2,
    tzinfo=timezone.utc,
)

scan = ScanMetadata(
    scan_id="SF-SCAN-001",
    status="completed",
    started_at=started,
    completed_at=completed,
    integrations=[
        "sast",
        "sca",
        "dast",
    ],
)

assert scan.scan_id == "SF-SCAN-001"
assert scan.status == "completed"
assert scan.started_at == started
assert scan.completed_at == completed
assert scan.integrations == [
    "sast",
    "sca",
    "dast",
]
```

def test_report_finding_contains_security_context():
"""Report findings should preserve security context."""
finding = ReportFinding(
finding_id="SF-BOLA-001",
title="Broken Object-Level Authorization",
source="correlation",
source_finding_ids=[
"API-BOLA-001",
"DAST-BOLA-001",
],
application="SecureCommerce",
asset="SecureCommerce API",
endpoint="/api/orders/{order_id}",
parameter="order_id",
cwe="CWE-639",
owasp=(
"API1:2023-Broken Object Level "
"Authorization"
),
security_requirement="SF-AUTHZ-001",
severity="high",
confidence="confirmed",
description="Unauthorized object access.",
impact="Customer data may be exposed.",
remediation="Enforce object ownership.",
status="open",
validation_status="confirmed",
regression_test="BOLA-001",
evidence_count=2,
)

```
assert finding.finding_id == "SF-BOLA-001"
assert finding.source == "correlation"
assert finding.source_finding_ids == [
    "API-BOLA-001",
    "DAST-BOLA-001",
]
assert finding.cwe == "CWE-639"
assert finding.security_requirement == (
    "SF-AUTHZ-001"
)
assert finding.evidence_count == 2
```

def test_risk_report_preserves_risk_factors():
"""Risk reports should retain the factors used in evaluation."""
risk = RiskReport(
overall_score=8.5,
highest_severity="high",
confirmed_critical=0,
confirmed_high=2,
risk_factors={
"internet_exposure": True,
"sensitive_data": True,
"exploit_evidence": False,
},
)

```
assert risk.overall_score == 8.5
assert risk.highest_severity == "high"
assert risk.confirmed_high == 2
assert risk.risk_factors["internet_exposure"] is True
```

def test_policy_report_preserves_gate_configuration():
"""Policy reports should preserve configured release actions."""
policy = PolicyReport(
policy_name="default",
critical_action="block",
high_action="block",
medium_action="review",
low_action="pass",
info_action="pass",
tool_errors=[
"SAST execution failed."
],
regression_failures=[
"BOLA-001",
],
)

```
assert policy.policy_name == "default"
assert policy.critical_action == "block"
assert policy.high_action == "block"
assert policy.medium_action == "review"
assert policy.low_action == "pass"
assert policy.info_action == "pass"
assert policy.tool_errors == [
    "SAST execution failed."
]
assert policy.regression_failures == [
    "BOLA-001"
]
```

def test_remediation_report_tracks_lifecycle_counts():
"""Remediation reports should track finding lifecycle counts."""
remediation = RemediationReport(
open_findings=3,
remediated_findings=1,
verified_findings=2,
pending_retests=1,
)

```
assert remediation.open_findings == 3
assert remediation.remediated_findings == 1
assert remediation.verified_findings == 2
assert remediation.pending_retests == 1
```

def test_regression_test_report_preserves_result():
"""Individual regression results should be represented accurately."""
test = RegressionTestReport(
test_id="BOLA-001",
requirement="SF-AUTHZ-001",
status="failed",
expected_result="HTTP 403",
actual_result="HTTP 200",
message="Authorization bypass remains exploitable.",
)

```
assert test.test_id == "BOLA-001"
assert test.requirement == "SF-AUTHZ-001"
assert test.status == "failed"
assert test.expected_result == "HTTP 403"
assert test.actual_result == "HTTP 200"
```

def test_regression_report_tracks_suite_summary():
"""Regression reports should summarize test execution."""
regression = RegressionReport(
suite="SecureCommerce Security Regression Suite",
tests_total=2,
tests_passed=1,
tests_failed=1,
tests=[
RegressionTestReport(
test_id="BOLA-001",
requirement="SF-AUTHZ-001",
status="failed",
),
RegressionTestReport(
test_id="SECRET-001",
requirement="SF-SECRET-001",
status="passed",
),
],
)

```
assert regression.tests_total == 2
assert regression.tests_passed == 1
assert regression.tests_failed == 1
assert len(regression.tests) == 2
```

def test_decision_report_represents_blocked_release():
"""A blocked release should explicitly prevent release."""
decision = DecisionReport(
status="block",
reason="Confirmed critical finding.",
release_allowed=False,
)

```
assert decision.status == "block"
assert decision.release_allowed is False
assert decision.reason
```

def test_security_report_contains_all_major_sections():
"""A complete security report should contain every major section."""
report = SecurityReport(
release=ReleaseMetadata(
release_id="release-001",
application="SecureCommerce",
version="0.1.0",
environment="lab",
profile="standard",
),
scan=ScanMetadata(
scan_id="SF-SCAN-001",
status="completed",
),
risk=RiskReport(
overall_score=9.0,
highest_severity="critical",
),
policy=PolicyReport(
policy_name="default",
critical_action="block",
high_action="block",
medium_action="review",
low_action="pass",
),
remediation=RemediationReport(),
regression=RegressionReport(
suite="SecureCommerce Security Regression Suite"
),
decision=DecisionReport(
status="block",
reason="Critical finding.",
release_allowed=False,
),
)

```
assert report.release.application == (
    "SecureCommerce"
)
assert report.scan.scan_id == "SF-SCAN-001"
assert report.risk.highest_severity == "critical"
assert report.policy.policy_name == "default"
assert report.regression.suite == (
    "SecureCommerce Security Regression Suite"
)
assert report.decision.release_allowed is False
assert report.generated_at.tzinfo == timezone.utc
```
