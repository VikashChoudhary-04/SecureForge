```python id="q8w4m1"
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
    ToolExecutionResult,
)
from secureforge.core.scan.orchestrator import (
    SecurityScanResult,
)
from secureforge.core.scan.security_pipeline import (
    SecurityPipelineResult,
)
from secureforge.integrations.base import (
    IntegrationResult,
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
from secureforge.regression import (
    RegressionGateDecision,
    RegressionResult,
    RegressionStatus,
    RegressionSuiteResult,
)


@pytest.fixture
def sample_evidence() -> Evidence:
    """Return deterministic sample finding evidence."""
    return Evidence(
        source="dast",
        type="http_response",
        content=(
            "The target returned an unauthorized resource."
        ),
        location="/api/orders/1001",
    )


@pytest.fixture
def sample_finding(
    sample_evidence: Evidence,
) -> Finding:
    """Return a representative normalized security finding."""
    return Finding(
        finding_id="SF-0001",
        title="Broken Object Level Authorization",
        source="dast",
        asset="api",
        application="securecommerce",
        endpoint="/api/orders/1001",
        parameter="id",
        cwe="CWE-639",
        owasp_mapping="API1:2023",
        security_requirement="SF-AUTHZ-001",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        evidence=[sample_evidence],
        description=(
            "An authenticated user can access an object "
            "belonging to another user."
        ),
        impact=(
            "Unauthorized access to another user's order."
        ),
        remediation=(
            "Enforce object-level authorization before "
            "returning the requested resource."
        ),
        status=FindingStatus.OPEN,
        validation_status=ValidationStatus.VALIDATED,
        first_seen=datetime(
            2026,
            9,
            27,
            10,
            0,
            tzinfo=timezone.utc,
        ),
        last_seen=datetime(
            2026,
            9,
            27,
            10,
            0,
            tzinfo=timezone.utc,
        ),
        regression_test="BOLA-001",
        correlation_ids=["CORR-0001"],
    )


@pytest.fixture
def sample_findings(
    sample_finding: Finding,
) -> list[Finding]:
    """Return a deterministic finding collection."""
    second = sample_finding.model_copy(
        deep=True
    )

    second.finding_id = "SF-0002"
    second.title = "SQL Injection"
    second.source = "sast"
    second.endpoint = "/search"
    second.parameter = "query"
    second.cwe = "CWE-89"
    second.owasp_mapping = "A03:2021"
    second.security_requirement = "SF-INPUT-001"
    second.severity = Severity.CRITICAL
    second.regression_test = "SQLI-001"
    second.correlation_ids = ["CORR-0002"]

    return [
        sample_finding,
        second,
    ]


@pytest.fixture
def sample_risk_assessment(
    sample_findings: list[Finding],
) -> RiskAssessment:
    """Return a deterministic risk assessment."""
    return RiskAssessment(
        score=90.0,
        highest_severity=Severity.CRITICAL,
        finding_count=len(sample_findings),
        evaluated_at=(
            "2026-09-27T10:05:00+00:00"
        ),
    )


@pytest.fixture
def sample_policy_decision() -> PolicyDecision:
    """Return a deterministic blocking policy decision."""
    return PolicyDecision(
        policy_name="default",
        action="block",
        allowed=False,
        reason=(
            "A confirmed critical finding violates "
            "the release policy."
        ),
        violations=[
            "SF-0002",
        ],
    )


@pytest.fixture
def sample_release_gate_decision() -> ReleaseGateDecision:
    """Return a deterministic blocked release decision."""
    return ReleaseGateDecision(
        status=ReleaseGateStatus.BLOCKED,
        reason=(
            "The release contains a confirmed critical "
            "security finding."
        ),
        release_allowed=False,
    )


@pytest.fixture
def sample_regression_result() -> RegressionSuiteResult:
    """Return a passing regression-suite result."""
    return RegressionSuiteResult(
        suite_id="securecommerce-regression",
        status=RegressionStatus.PASSED,
        total=2,
        passed=2,
        failed=0,
        errors=0,
        skipped=0,
        results=[
            RegressionResult(
                test_id="BOLA-001",
                status=RegressionStatus.PASSED,
                message=(
                    "BOLA protection verified."
                ),
            ),
            RegressionResult(
                test_id="SQLI-001",
                status=RegressionStatus.PASSED,
                message=(
                    "SQL injection protection verified."
                ),
            ),
        ],
    )


@pytest.fixture
def sample_regression_gate() -> RegressionGateDecision:
    """Return a passing regression-gate decision."""
    return RegressionGateDecision(
        allowed=True,
        status="passed",
        reason=(
            "All executed security regression tests passed."
        ),
        failed_tests=(),
        errored_tests=(),
        skipped_tests=(),
    )


@pytest.fixture
def sample_scan_execution() -> ScanExecution:
    """Return a deterministic scan execution."""
    return ScanExecution(
        scan_id="scan-001",
        profile="standard",
        target="http://localhost:5000",
        source_path="/workspace/securecommerce",
        status=ScanStatus.COMPLETED,
        findings=[],
        errors=[],
        tool_results=[],
        started_at=(
            "2026-09-27T10:00:00+00:00"
        ),
        completed_at=(
            "2026-09-27T10:05:00+00:00"
        ),
    )


@pytest.fixture
def sample_pipeline_result(
    sample_findings: list[Finding],
    sample_risk_assessment: RiskAssessment,
    sample_policy_decision: PolicyDecision,
    sample_release_gate_decision: ReleaseGateDecision,
    sample_regression_result: RegressionSuiteResult,
    sample_regression_gate: RegressionGateDecision,
) -> SecurityPipelineResult:
    """Return a complete deterministic pipeline result."""
    return SecurityPipelineResult(
        findings=sample_findings,
        risk=sample_risk_assessment,
        policy=sample_policy_decision,
        regression=sample_regression_result,
        regression_gate=sample_regression_gate,
        release_gate=sample_release_gate_decision,
    )


@pytest.fixture
def sample_scan_result(
    sample_scan_execution: ScanExecution,
    sample_findings: list[Finding],
    sample_pipeline_result: SecurityPipelineResult,
) -> SecurityScanResult:
    """Return a complete deterministic scan result."""
    execution = sample_scan_execution.model_copy(
        deep=True
    )

    execution.findings = list(
        sample_findings
    )

    return SecurityScanResult(
        execution=execution,
        findings=list(sample_findings),
        pipeline=sample_pipeline_result,
    )


@pytest.fixture
def sample_security_report(
    sample_findings: list[Finding],
    sample_risk_assessment: RiskAssessment,
    sample_policy_decision: PolicyDecision,
    sample_release_gate_decision: ReleaseGateDecision,
    sample_regression_result: RegressionSuiteResult,
    sample_regression_gate: RegressionGateDecision,
) -> SecurityReport:
    """Return a complete deterministic security report."""
    report_findings = [
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
            regression_test=finding.regression_test,
            correlation_ids=list(
                finding.correlation_ids
            ),
        )
        for finding in sample_findings
    ]

    regression = RegressionReport(
        suite_id=sample_regression_result.suite_id,
        status=sample_regression_result.status.value,
        total=sample_regression_result.total,
        passed=sample_regression_result.passed,
        failed=sample_regression_result.failed,
        errors=sample_regression_result.errors,
        skipped=sample_regression_result.skipped,
        tests=[
            RegressionTestReport(
                test_id=result.test_id,
                status=result.status.value,
                message=result.message,
            )
            for result in sample_regression_result.results
        ],
    )

    regression_gate = RegressionGateReport(
        allowed=sample_regression_gate.allowed,
        blocked=sample_regression_gate.blocked,
        status=sample_regression_gate.status,
        reason=sample_regression_gate.reason,
        failed_tests=list(
            sample_regression_gate.failed_tests
        ),
        errored_tests=list(
            sample_regression_gate.errored_tests
        ),
        skipped_tests=list(
            sample_regression_gate.skipped_tests
        ),
        failures=list(
            sample_regression_gate.failures
        ),
    )

    return SecurityReport(
        release=ReleaseMetadata(
            application="securecommerce",
            version="1.0.0",
            commit_sha="abc123",
            environment="test",
        ),
        scan=ScanMetadata(
            scan_id="scan-001",
            profile="standard",
            target="http://localhost:5000",
            started_at=(
                "2026-09-27T10:00:00+00:00"
            ),
            completed_at=(
                "2026-09-27T10:05:00+00:00"
            ),
        ),
        findings=report_findings,
        risk=RiskReport(
            score=sample_risk_assessment.score,
            highest_severity=(
                sample_risk_assessment
                .highest_severity
                .value
            ),
            finding_count=(
                sample_risk_assessment
                .finding_count
            ),
            evaluated_at=(
                sample_risk_assessment
                .evaluated_at
            ),
        ),
        policy=PolicyReport(
            policy_name=(
                sample_policy_decision
                .policy_name
            ),
            action=sample_policy_decision.action,
            allowed=sample_policy_decision.allowed,
            reason=sample_policy_decision.reason,
            violations=list(
                sample_policy_decision.violations
            ),
        ),
        decision=DecisionReport(
            status=(
                sample_release_gate_decision
                .status
                .value
            ),
            reason=(
                sample_release_gate_decision
                .reason
            ),
            release_allowed=(
                sample_release_gate_decision
                .release_allowed
            ),
        ),
        remediation=RemediationReport(
            total=len(sample_findings),
            open=sum(
                finding.status == FindingStatus.OPEN
                for finding in sample_findings
            ),
            remediated=sum(
                finding.status
                == FindingStatus.REMEDIATED
                for finding in sample_findings
            ),
            verified=sum(
                finding.validation_status
                == ValidationStatus.VERIFIED
                for finding in sample_findings
            ),
        ),
        regression=regression,
        regression_gate=regression_gate,
        generated_at=(
            "2026-09-27T10:05:00+00:00"
        ),
    )


class FakeScanRunner:
    """Deterministic scan runner for orchestration tests."""

    def __init__(
        self,
        sample_findings: list[Finding],
    ) -> None:
        self.sample_findings = sample_findings
        self.last_source_path: str | None = None

    def run(
        self,
        *,
        scan_id: str,
        profile: str,
        target: str,
        source_path: str | None = None,
    ) -> ScanExecution:
        """Return a deterministic completed scan."""
        self.last_source_path = source_path

        return ScanExecution(
            scan_id=scan_id,
            profile=profile,
            target=target,
            source_path=source_path,
            status=ScanStatus.COMPLETED,
            findings=list(
                self.sample_findings
            ),
            errors=[],
            tool_results=[],
            started_at=(
                "2026-09-27T10:00:00+00:00"
            ),
            completed_at=(
                "2026-09-27T10:05:00+00:00"
            ),
        )


@pytest.fixture
def fake_scan_runner(
    sample_findings: list[Finding],
) -> FakeScanRunner:
    """Return a deterministic fake scan runner."""
    return FakeScanRunner(
        sample_findings
    )
```
