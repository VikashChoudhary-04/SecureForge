"""Tests for the SecureForge security report builder."""

from **future** import annotations

from datetime import datetime, timezone

from secureforge.core.findings import (
Confidence,
Evidence,
Finding,
FindingStatus,
Severity,
ValidationStatus,
)
from secureforge.core.policy import PolicyDecision
from secureforge.core.release_gate import (
ReleaseGateDecision,
ReleaseGateStatus,
)
from secureforge.core.risk import RiskAssessment
from secureforge.reporting import SecurityReportBuilder

def build_finding(
*,
finding_id: str = "SF-BOLA-001",
severity: Severity = Severity.HIGH,
status: FindingStatus = FindingStatus.OPEN,
validation_status: ValidationStatus = (
ValidationStatus.CONFIRMED
),
) -> Finding:
"""Build a representative domain finding."""
finding = Finding(
finding_id=finding_id,
title="Broken Object-Level Authorization",
source="api",
source_finding_id="API-BOLA-001",
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
severity=severity,
confidence=Confidence.CONFIRMED,
description="Unauthorized order access.",
impact="Customer order data may be exposed.",
remediation="Enforce object-level authorization.",
status=status,
validation_status=validation_status,
regression_test="BOLA-001",
evidence=[
Evidence(
evidence_id="EV-001",
source="api",
description="User accessed another user's order.",
data={
"request_user_id": 2,
"order_owner_id": 3,
},
)
],
)

```
return finding
```

def build_risk() -> RiskAssessment:
"""Build a representative risk assessment."""
return RiskAssessment(
score=8.5,
highest_severity="high",
confirmed_critical=0,
confirmed_high=1,
factors={
"internet_exposure": True,
"sensitive_data": True,
"exploit_evidence": True,
},
)

def build_policy() -> PolicyDecision:
"""Build a representative policy decision."""
return PolicyDecision(
policy_name="default",
actions={
"critical": "block",
"high": "block",
"medium": "review",
"low": "pass",
"info": "pass",
},
tool_errors=[],
regression_failures=[],
exceptions=[],
)

def build_release_gate() -> ReleaseGateDecision:
"""Build a representative blocked release decision."""
return ReleaseGateDecision(
status=ReleaseGateStatus.BLOCK,
reason=(
"Confirmed high-severity finding "
"violates the release policy."
),
release_allowed=False,
)

def test_builder_creates_complete_report():
"""Builder should create a complete security report."""
builder = SecurityReportBuilder()

```
started_at = datetime(
    2026,
    9,
    27,
    8,
    0,
    tzinfo=timezone.utc,
)

completed_at = datetime(
    2026,
    9,
    27,
    8,
    2,
    tzinfo=timezone.utc,
)

report = builder.build(
    release_id="release-001",
    application="SecureCommerce",
    version="0.1.0",
    environment="lab",
    profile="standard",
    scan_id="SF-SCAN-001",
    scan_status="completed",
    integrations=[
        "sast",
        "api",
        "dast",
    ],
    findings=[
        build_finding()
    ],
    risk=build_risk(),
    policy=build_policy(),
    release_gate=build_release_gate(),
    commit_sha="lab-commit-001",
    started_at=started_at,
    completed_at=completed_at,
)

assert report.release.release_id == (
    "release-001"
)
assert report.release.application == (
    "SecureCommerce"
)
assert report.release.commit_sha == (
    "lab-commit-001"
)

assert report.scan.scan_id == (
    "SF-SCAN-001"
)
assert report.scan.status == "completed"
assert report.scan.integrations == [
    "sast",
    "api",
    "dast",
]

assert len(report.findings) == 1
assert report.findings[0].finding_id == (
    "SF-BOLA-001"
)
assert report.findings[0].source == "api"
assert report.findings[0].evidence_count == 1

assert report.risk.overall_score == 8.5
assert report.risk.highest_severity == "high"

assert report.policy.policy_name == "default"
assert report.policy.high_action == "block"

assert report.decision.status == "block"
assert report.decision.release_allowed is False
```

def test_builder_preserves_source_finding_id():
"""A finding's original source identifier should remain traceable."""
builder = SecurityReportBuilder()

```
report = builder.build(
    release_id="release-002",
    application="SecureCommerce",
    version="0.1.0",
    environment="lab",
    profile="quick",
    scan_id="SF-SCAN-002",
    scan_status="completed",
    integrations=["sast"],
    findings=[
        build_finding()
    ],
    risk=build_risk(),
    policy=build_policy(),
    release_gate=build_release_gate(),
)

finding = report.findings[0]

assert finding.source_finding_ids == [
    "API-BOLA-001"
]
```

def test_builder_counts_remediation_states():
"""Builder should summarize the finding lifecycle correctly."""
builder = SecurityReportBuilder()

```
open_finding = build_finding(
    finding_id="SF-OPEN-001",
    status=FindingStatus.OPEN,
)

remediated_finding = build_finding(
    finding_id="SF-REMEDIATED-001",
    status=FindingStatus.REMEDIATED,
)

verified_finding = build_finding(
    finding_id="SF-VERIFIED-001",
    status=FindingStatus.VERIFIED,
)

report = builder.build(
    release_id="release-003",
    application="SecureCommerce",
    version="0.1.0",
    environment="lab",
    profile="standard",
    scan_id="SF-SCAN-003",
    scan_status="completed",
    integrations=["dast"],
    findings=[
        open_finding,
        remediated_finding,
        verified_finding,
    ],
    risk=build_risk(),
    policy=build_policy(),
    release_gate=build_release_gate(),
)

assert report.remediation.open_findings == 1
assert report.remediation.remediated_findings == 1
assert report.remediation.verified_findings == 1
assert report.remediation.pending_retests == 1
```

def test_builder_calculates_regression_summary():
"""Builder should calculate passed and failed regression counts."""
builder = SecurityReportBuilder()

```
regression_results = [
    {
        "test_id": "BOLA-001",
        "requirement": "SF-AUTHZ-001",
        "status": "failed",
        "expected_result": "HTTP 403",
        "actual_result": "HTTP 200",
        "message": "Authorization bypass remains.",
    },
    {
        "test_id": "SECRET-001",
        "requirement": "SF-SECRET-001",
        "status": "passed",
        "expected_result": "No hardcoded secret",
        "actual_result": "No hardcoded secret",
    },
    {
        "test_id": "XSS-001",
        "requirement": "SF-INPUT-001",
        "status": "passed",
    },
]

report = builder.build(
    release_id="release-004",
    application="SecureCommerce",
    version="0.1.0",
    environment="lab",
    profile="full",
    scan_id="SF-SCAN-004",
    scan_status="completed",
    integrations=[
        "sast",
        "secrets",
        "dast",
    ],
    findings=[],
    risk=build_risk(),
    policy=build_policy(),
    release_gate=build_release_gate(),
    regression_results=regression_results,
)

assert report.regression.tests_total == 3
assert report.regression.tests_passed == 2
assert report.regression.tests_failed == 1

assert report.regression.tests[0].test_id == (
    "BOLA-001"
)
assert report.regression.tests[0].status == (
    "failed"
)
```

def test_builder_preserves_metadata():
"""Additional report metadata should remain intact."""
builder = SecurityReportBuilder()

```
report = builder.build(
    release_id="release-005",
    application="SecureCommerce",
    version="0.1.0",
    environment="lab",
    profile="standard",
    scan_id="SF-SCAN-005",
    scan_status="completed",
    integrations=["api"],
    findings=[],
    risk=build_risk(),
    policy=build_policy(),
    release_gate=build_release_gate(),
    metadata={
        "runner": "secureforge",
        "lab_mode": True,
        "source": "integration-test",
    },
)

assert report.metadata == {
    "runner": "secureforge",
    "lab_mode": True,
    "source": "integration-test",
}
```
