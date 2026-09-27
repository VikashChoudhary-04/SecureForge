```python id="v3m8qx"
"""Adapters for building security reports from scan results."""

from __future__ import annotations

from secureforge.core.scan.orchestrator import (
    SecurityScanResult,
)

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


def build_scan_report(
    result: SecurityScanResult,
    *,
    release: ReleaseMetadata,
    scan: ScanMetadata,
    generated_at: str | None = None,
) -> SecurityReport:
    """Build a complete security report from a scan result."""
    findings = [
        ReportFinding(
            finding_id=finding.finding_id,
            title=finding.title,
            source=finding.source,
            asset=finding.asset,
            application=finding.application,
            endpoint=finding.endpoint,
            parameter=finding.parameter,
            cwe=finding.cwe,
            owasp_mapping=finding.owasp_mapping,
            security_requirement=(
                finding.security_requirement
            ),
            severity=finding.severity.value,
            confidence=finding.confidence.value,
            evidence=[
                evidence.model_dump(
                    mode="json"
                )
                for evidence in finding.evidence
            ],
            description=finding.description,
            impact=finding.impact,
            remediation=finding.remediation,
            status=finding.status.value,
            validation_status=(
                finding.validation_status.value
            ),
            first_seen=str(
                finding.first_seen
            ),
            last_seen=str(
                finding.last_seen
            ),
            regression_test=(
                finding.regression_test
            ),
            correlation_ids=list(
                finding.correlation_ids
            ),
        )
        for finding in result.findings
    ]

    risk = RiskReport(
        score=result.pipeline.risk.score,
        highest_severity=(
            result.pipeline.risk
            .highest_severity.value
        ),
        finding_count=(
            result.pipeline.risk.finding_count
        ),
        evaluated_at=(
            result.pipeline.risk.evaluated_at
        ),
    )

    policy = PolicyReport(
        policy_name=(
            result.pipeline.policy.policy_name
        ),
        action=(
            result.pipeline.policy.action
        ),
        allowed=(
            result.pipeline.policy.allowed
        ),
        reason=(
            result.pipeline.policy.reason
        ),
        violations=list(
            result.pipeline.policy.violations
        ),
    )

    decision = DecisionReport(
        status=(
            result.pipeline.release_gate
            .status.value
        ),
        reason=(
            result.pipeline.release_gate
            .reason
        ),
        release_allowed=(
            result.pipeline.release_gate
            .release_allowed
        ),
    )

    regression = RegressionReport(
        suite_id="",
        status="not_run",
        total=0,
        passed=0,
        failed=0,
        errors=0,
        skipped=0,
        tests=[],
    )

    if result.pipeline.regression is not None:
        suite = result.pipeline.regression

        regression = RegressionReport(
            suite_id=suite.suite_id,
            status=suite.status.value,
            total=suite.total,
            passed=suite.passed,
            failed=suite.failed,
            errors=suite.errors,
            skipped=suite.skipped,
            tests=[
                {
                    "test_id": item.test_id,
                    "status": item.status.value,
                    "message": item.message,
                }
                for item in suite.results
            ],
        )

    regression_gate = None

    if result.pipeline.regression_gate is not None:
        gate = result.pipeline.regression_gate

        regression_gate = RegressionGateReport(
            allowed=gate.allowed,
            blocked=gate.blocked,
            status=gate.status,
            reason=gate.reason,
            failed_tests=list(
                gate.failed_tests
            ),
            errored_tests=list(
                gate.errored_tests
            ),
            skipped_tests=list(
                gate.skipped_tests
            ),
            failures=list(
                gate.failures
            ),
        )

    remediation = RemediationReport(
        total=len(findings),
        open=sum(
            1
            for finding in result.findings
            if finding.status.value == "open"
        ),
        remediated=sum(
            1
            for finding in result.findings
            if finding.status.value == "remediated"
        ),
        verified=sum(
            1
            for finding in result.findings
            if finding.validation_status.value == "verified"
        ),
    )

    return SecurityReport(
        release=release,
        scan=scan,
        findings=findings,
        risk=risk,
        policy=policy,
        decision=decision,
        remediation=remediation,
        regression=regression,
        regression_gate=regression_gate,
        generated_at=(
            generated_at
            if generated_at is not None
            else scan.completed_at
        ),
    )
```
