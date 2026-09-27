"""Scan-result adapters for SecureForge reporting."""

from **future** import annotations

from datetime import datetime, timezone

from secureforge.core.scan.orchestrator import SecurityScanResult

from .models import (
DecisionReport,
PolicyReport,
RegressionGateReport,
RegressionReport,
ReleaseMetadata,
RemediationReport,
ReportFinding,
RiskReport,
ScanMetadata,
SecurityReport,
)
from .regression import build_regression_report
from .regression_gate import build_regression_gate_report

def build_scan_report(
result: SecurityScanResult,
*,
release: ReleaseMetadata,
scan: ScanMetadata,
generated_at: str | None = None,
) -> SecurityReport:
"""Convert a complete scan result into a security report."""
findings = [
ReportFinding(
finding_id=finding.finding_id,
title=finding.title,
source=finding.source,
asset=finding.asset,
application=finding.application,
endpoint=finding.endpoint,
parameter=finding.parameter,
severity=finding.severity.value,
confidence=finding.confidence.value,
status=finding.status.value,
validation_status=(
finding.validation_status.value
),
cwe=finding.cwe,
owasp_mapping=finding.owasp_mapping,
security_requirement=(
finding.security_requirement
),
description=finding.description,
impact=finding.impact,
remediation=finding.remediation,
evidence=[
evidence.model_dump()
for evidence in finding.evidence
],
correlations=list(
finding.correlations
),
regression_test=(
finding.regression_test
),
)
for finding in result.findings
]

```
regression = (
    build_regression_report(
        result.pipeline.regression
    )
    if result.pipeline.regression is not None
    else RegressionReport(
        suite_id="not-run",
        suite_name="Regression Testing",
        status="skipped",
        total=0,
        passed=0,
        failed=0,
        errors=0,
        skipped=0,
        tests=[],
        started_at=None,
        completed_at=None,
        duration_seconds=0.0,
    )
)

regression_gate = (
    build_regression_gate_report(
        result.pipeline.regression_gate
    )
    if result.pipeline.regression_gate is not None
    else None
)

risk = result.pipeline.risk

risk_report = RiskReport(
    score=risk.score,
    highest_severity=(
        risk.highest_severity.value
    ),
    confirmed_critical=(
        risk.confirmed_critical
    ),
    confirmed_high=(
        risk.confirmed_high
    ),
    factors=[
        factor.model_dump()
        if hasattr(
            factor,
            "model_dump",
        )
        else factor
        for factor in risk.factors
    ],
)

policy = result.pipeline.policy

policy_report = PolicyReport(
    policy_name=policy.policy_name,
    actions=[
        action.model_dump()
        if hasattr(
            action,
            "model_dump",
        )
        else action
        for action in policy.actions
    ],
    tool_errors=list(
        policy.tool_errors
    ),
    regression_failures=list(
        policy.regression_failures
    ),
    exceptions=[
        exception.model_dump()
        if hasattr(
            exception,
            "model_dump",
        )
        else exception
        for exception in policy.exceptions
    ],
)

decision = result.pipeline.release_gate

decision_report = DecisionReport(
    status=decision.status.value,
    reason=decision.reason,
    release_allowed=decision.release_allowed,
)

return SecurityReport(
    release=release,
    scan=scan,
    findings=findings,
    risk=risk_report,
    policy=policy_report,
    remediation=RemediationReport(
        total=0,
        open=0,
        in_progress=0,
        resolved=0,
        verified=0,
        items=[],
    ),
    regression=regression,
    regression_gate=regression_gate,
    decision=decision_report,
    generated_at=(
        generated_at
        if generated_at is not None
        else datetime.now(
            timezone.utc
        ).isoformat()
    ),
)
```
