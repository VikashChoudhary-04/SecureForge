```python id="r3m7x1"
"""Tests for SecureForge reporting models."""

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


def test_release_metadata_model() -> None:
    """Release metadata stores release identity."""
    release = ReleaseMetadata(
        application="securecommerce",
        version="1.0.0",
        commit_sha="abc123",
        environment="test",
    )

    assert release.application == "securecommerce"
    assert release.version == "1.0.0"
    assert release.commit_sha == "abc123"
    assert release.environment == "test"


def test_scan_metadata_model() -> None:
    """Scan metadata stores scan execution information."""
    scan = ScanMetadata(
        scan_id="scan-001",
        profile="standard",
        target="http://localhost:5000",
        started_at="2026-09-27T10:00:00+00:00",
        completed_at="2026-09-27T10:05:00+00:00",
    )

    assert scan.scan_id == "scan-001"
    assert scan.profile == "standard"
    assert scan.target == "http://localhost:5000"


def test_report_finding_model() -> None:
    """Report findings preserve normalized security evidence."""
    finding = ReportFinding(
        finding_id="SF-001",
        title="BOLA in order endpoint",
        source="dast",
        asset="api",
        application="securecommerce",
        endpoint="/api/orders/1001",
        parameter="id",
        cwe="CWE-639",
        owasp_mapping="API1:2023",
        security_requirement="SF-AUTHZ-001",
        severity="high",
        confidence="confirmed",
        evidence=[
            {
                "type": "http_response",
                "content": "Order belonging to another user was returned.",
            }
        ],
        description="Object authorization is missing.",
        impact="Unauthorized users can access another user's order.",
        remediation="Enforce object-level authorization.",
        status="open",
        validation_status="validated",
        first_seen="2026-09-27T10:00:00+00:00",
        last_seen="2026-09-27T10:00:00+00:00",
        regression_test="BOLA-001",
        correlation_ids=["CORR-001"],
    )

    assert finding.finding_id == "SF-001"
    assert finding.severity == "high"
    assert finding.confidence == "confirmed"
    assert finding.regression_test == "BOLA-001"
    assert finding.correlation_ids == ["CORR-001"]


def test_risk_report_model() -> None:
    """Risk report stores calculated risk information."""
    risk = RiskReport(
        score=85.0,
        highest_severity="high",
        finding_count=3,
        evaluated_at="2026-09-27T10:05:00+00:00",
    )

    assert risk.score == 85.0
    assert risk.highest_severity == "high"
    assert risk.finding_count == 3


def test_policy_report_model() -> None:
    """Policy report stores policy evaluation results."""
    policy = PolicyReport(
        policy_name="default",
        action="block",
        allowed=False,
        reason="High severity confirmed finding.",
        violations=["SF-001"],
    )

    assert policy.policy_name == "default"
    assert policy.action == "block"
    assert policy.allowed is False
    assert policy.violations == ["SF-001"]


def test_decision_report_model() -> None:
    """Decision report stores the final release decision."""
    decision = DecisionReport(
        status="blocked",
        reason="Security policy blocked the release.",
        release_allowed=False,
    )

    assert decision.status == "blocked"
    assert decision.release_allowed is False


def test_remediation_report_model() -> None:
    """Remediation report stores lifecycle counts."""
    remediation = RemediationReport(
        total=5,
        open=3,
        remediated=1,
        verified=1,
    )

    assert remediation.total == 5
    assert remediation.open == 3
    assert remediation.remediated == 1
    assert remediation.verified == 1


def test_regression_test_report_model() -> None:
    """Regression-test reports store individual test results."""
    result = RegressionTestReport(
        test_id="BOLA-001",
        status="passed",
        message="BOLA protection verified.",
    )

    assert result.test_id == "BOLA-001"
    assert result.status == "passed"
    assert result.message == "BOLA protection verified."


def test_regression_report_model() -> None:
    """Regression reports store suite-level results."""
    regression = RegressionReport(
        suite_id="securecommerce-regression",
        status="passed",
        total=2,
        passed=2,
        failed=0,
        errors=0,
        skipped=0,
        tests=[
            RegressionTestReport(
                test_id="BOLA-001",
                status="passed",
                message="BOLA protection verified.",
            ),
            RegressionTestReport(
                test_id="SQLI-001",
                status="passed",
                message="SQL injection protection verified.",
            ),
        ],
    )

    assert regression.suite_id == "securecommerce-regression"
    assert regression.status == "passed"
    assert regression.total == 2
    assert regression.passed == 2
    assert regression.failed == 0
    assert len(regression.tests) == 2
    assert regression.tests[0].test_id == "BOLA-001"


def test_regression_gate_report_model() -> None:
    """Regression-gate reports preserve release-gate evidence."""
    gate = RegressionGateReport(
        allowed=False,
        blocked=True,
        status="failed",
        reason="A security regression test failed.",
        failed_tests=["BOLA-001"],
        errored_tests=[],
        skipped_tests=[],
        failures=["BOLA-001"],
    )

    assert gate.allowed is False
    assert gate.blocked is True
    assert gate.status == "failed"
    assert gate.failed_tests == ["BOLA-001"]
    assert gate.failures == ["BOLA-001"]


def test_security_report_model(
    sample_security_report,
) -> None:
    """Security report combines all report sections."""
    assert isinstance(
        sample_security_report,
        SecurityReport,
    )

    assert isinstance(
        sample_security_report.release,
        ReleaseMetadata,
    )

    assert isinstance(
        sample_security_report.scan,
        ScanMetadata,
    )

    assert isinstance(
        sample_security_report.risk,
        RiskReport,
    )

    assert isinstance(
        sample_security_report.policy,
        PolicyReport,
    )

    assert isinstance(
        sample_security_report.decision,
        DecisionReport,
    )
```
