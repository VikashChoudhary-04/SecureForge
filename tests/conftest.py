```python id="z2f6kp"
"""Shared pytest fixtures for SecureForge tests."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from secureforge.core.findings.models import (
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    Severity,
    ValidationStatus,
)
from secureforge.core.policy.models import (
    PolicyDecision,
)
from secureforge.core.release_gate.models import (
    ReleaseGateDecision,
    ReleaseGateStatus,
)
from secureforge.core.risk.models import (
    RiskAssessment,
)
from secureforge.core.scan.models import (
    ScanExecution,
    ScanStatus,
)
from secureforge.core.scan.orchestrator import (
    SecurityScanResult,
)
from secureforge.core.scan.security_pipeline import (
    SecurityPipelineResult,
)
from secureforge.reporting import (
    DecisionReport,
    PolicyReport,
    RegressionGateReport,
    RegressionReport,
    RegressionTestReport,
    ReleaseMetadata,
    RemediationReport,
    ReportFinding,
    RiskReport,
    ScanMetadata,
    SecurityReport,
)


@pytest.fixture
def sample_finding() -> Finding:
    """Return a representative normalized finding."""
    return Finding(
        finding_id="SF-0001",
        title="BOLA in order endpoint",
        source="dast",
        asset="securecommerce",
        application="securecommerce",
        endpoint="/api/orders/1",
        parameter="id",
        cwe="CWE-639",
        owasp_mapping="API1:2023",
        security_requirement="SF-AUTHZ-001",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        evidence=[
            Evidence(
                source="dast",
                type="http",
                content=(
                    "User A accessed User B's order."
                ),
            )
        ],
        description=(
            "The order endpoint does not enforce "
            "object-level authorization."
        ),
        impact=(
            "An authenticated user may access "
            "another user's order data."
        ),
        remediation=(
            "Enforce ownership checks before "
            "returning order objects."
        ),
        status=FindingStatus.OPEN,
        validation_status=(
            ValidationStatus.VALIDATED
        ),
        first_seen=(
            datetime(
                2026,
                9,
                27,
                tzinfo=timezone.utc,
            )
        ),
        last_seen=(
            datetime(
                2026,
                9,
                27,
                tzinfo=timezone.utc,
            )
        ),
        regression_test="BOLA-001",
    )


@pytest.fixture
def sample_scan_execution() -> ScanExecution:
    """Return a representative scan execution."""
    return ScanExecution(
        scan_id="scan-001",
        profile="standard",
        target="http://127.0.0.1:5000",
        status=ScanStatus.COMPLETED,
        tools=[
            "sast",
            "sca",
            "secrets",
            "api",
            "dast",
            "container",
        ],
        findings=[],
        warnings=[],
        errors=[],
        started_at=(
            "2026-09-27T10:00:00+00:00"
        ),
        completed_at=(
            "2026-09-27T10:01:00+00:00"
        ),
    )


@pytest.fixture
def sample_risk_assessment() -> RiskAssessment:
    """Return a representative risk assessment."""
    return RiskAssessment(
        score=72.0,
        highest_severity=Severity.HIGH,
        finding_count=1,
        evaluated_at=(
            "2026-09-27T10:01:00+00:00"
        ),
    )


@pytest.fixture
def sample_policy_decision() -> PolicyDecision:
    """Return a representative policy decision."""
    return PolicyDecision(
        policy_name="default",
        action="block",
        allowed=False,
        reason=(
            "A confirmed high-severity finding "
            "requires the release to be blocked."
        ),
        violations=[
            "SF-0001"
        ],
    )


@pytest.fixture
def sample_release_gate_decision() -> ReleaseGateDecision:
    """Return a representative release-gate decision."""
    return ReleaseGateDecision(
        status=ReleaseGateStatus.BLOCKED,
        reason=(
            "Release blocked by security policy."
        ),
        release_allowed=False,
    )


@pytest.fixture
def sample_pipeline_result(
    sample_finding,
    sample_risk_assessment,
    sample_policy_decision,
    sample_release_gate_decision,
) -> SecurityPipelineResult:
    """Return a representative security-pipeline result."""
    return SecurityPipelineResult(
        findings=[sample_finding],
        risk=sample_risk_assessment,
        policy=sample_policy_decision,
        regression=None,
        regression_gate=None,
        release_gate=sample_release_gate_decision,
    )


@pytest.fixture
def sample_scan_result(
    sample_scan_execution,
    sample_finding,
    sample_pipeline_result,
) -> SecurityScanResult:
    """Return a representative completed security scan."""
    sample_scan_execution.findings = [
        sample_finding
    ]

    return SecurityScanResult(
        execution=sample_scan_execution,
        findings=[sample_finding],
        pipeline=sample_pipeline_result,
    )


@pytest.fixture
def sample_security_report(
    sample_finding,
    sample_risk_assessment,
    sample_policy_decision,
    sample_release_gate_decision,
) -> SecurityReport:
    """Return a representative complete security report."""
    release = ReleaseMetadata(
        release_id="release-001",
        application="securecommerce",
        version="1.0.0",
        commit_sha="abc123",
        environment="lab",
        timestamp=(
            "2026-09-27T10:01:00+00:00"
        ),
    )

    scan = ScanMetadata(
        scan_id="scan-001",
        profile="standard",
        status="completed",
        tools=[
            "sast",
            "sca",
            "dast",
        ],
        started_at=(
            "2026-09-27T10:00:00+00:00"
        ),
        completed_at=(
            "2026-09-27T10:01:00+00:00"
        ),
        duration_seconds=60.0,
    )

    finding = ReportFinding(
        finding_id=sample_finding.finding_id,
        title=sample_finding.title,
        source=sample_finding.source,
        asset=sample_finding.asset,
        application=sample_finding.application,
        endpoint=sample_finding.endpoint,
        parameter=sample_finding.parameter,
        cwe=sample_finding.cwe,
        owasp_mapping=sample_finding.owasp_mapping,
        security_requirement=(
            sample_finding.security_requirement
        ),
        severity=sample_finding.severity.value,
        confidence=sample_finding.confidence.value,
        evidence=[
            evidence.model_dump()
            for evidence in sample_finding.evidence
        ],
        description=sample_finding.description,
        impact=sample_finding.impact,
        remediation=sample_finding.remediation,
        status=sample_finding.status.value,
        validation_status=(
            sample_finding.validation_status.value
        ),
        first_seen=str(
            sample_finding.first_seen
        ),
        last_seen=str(
            sample_finding.last_seen
        ),
        regression_test=sample_finding.regression_test,
        correlation_ids=[],
    )

    risk = RiskReport(
        score=sample_risk_assessment.score,
        highest_severity=(
            sample_risk_assessment
            .highest_severity.value
        ),
        finding_count=(
            sample_risk_assessment.finding_count
        ),
        evaluated_at=(
            sample_risk_assessment.evaluated_at
        ),
    )

    policy = PolicyReport(
        policy_name=sample_policy_decision.policy_name,
        action=sample_policy_decision.action,
        allowed=sample_policy_decision.allowed,
        reason=sample_policy_decision.reason,
        violations=list(
            sample_policy_decision.violations
        ),
    )

    decision = DecisionReport(
        status=sample_release_gate_decision.status.value,
        reason=sample_release_gate_decision.reason,
        release_allowed=(
            sample_release_gate_decision.release_allowed
        ),
    )

    return SecurityReport(
        release=release,
        scan=scan,
        findings=[finding],
        risk=risk,
        policy=policy,
        decision=decision,
        remediation=RemediationReport(
            total=0,
            open=0,
            remediated=0,
            verified=0,
        ),
        regression=RegressionReport(
            suite_id="securecommerce-regression",
            status="not_run",
            total=0,
            passed=0,
            failed=0,
            errors=0,
            skipped=0,
            tests=[],
        ),
        regression_gate=None,
        generated_at=(
            "2026-09-27T10:01:00+00:00"
        ),
    )
```
