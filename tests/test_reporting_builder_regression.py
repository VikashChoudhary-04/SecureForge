```python
"""Tests for regression data in the security report builder."""

from secureforge.reporting import (
    RegressionGateReport,
    RegressionReport,
    RegressionTestReport,
    ReleaseMetadata,
    ScanMetadata,
    SecurityReportBuilder,
)
from secureforge.regression import (
    RegressionGateDecision,
    RegressionResult,
    RegressionStatus,
    RegressionSuiteResult,
)


def test_builder_includes_regression_report(
    sample_findings,
    sample_risk_assessment,
    sample_policy_decision,
    sample_release_gate_decision,
) -> None:
    """Include regression-suite results in the security report."""
    builder = SecurityReportBuilder()

    regression = RegressionSuiteResult(
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
                message="BOLA protection verified.",
            ),
            RegressionResult(
                test_id="SQLI-001",
                status=RegressionStatus.PASSED,
                message="SQL injection protection verified.",
            ),
        ],
    )

    report = builder.build(
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
            started_at="2026-09-27T10:00:00+00:00",
            completed_at="2026-09-27T10:05:00+00:00",
        ),
        findings=sample_findings,
        risk=sample_risk_assessment,
        policy=sample_policy_decision,
        decision=sample_release_gate_decision,
        regression=regression,
    )

    assert report.regression is not None
    assert isinstance(
        report.regression,
        RegressionReport,
    )

    assert report.regression.suite_id == (
        "securecommerce-regression"
    )
    assert report.regression.status == "passed"
    assert report.regression.total == 2
    assert report.regression.passed == 2
    assert report.regression.failed == 0
    assert report.regression.errors == 0
    assert report.regression.skipped == 0

    assert len(report.regression.tests) == 2
    assert all(
        isinstance(
            item,
            RegressionTestReport,
        )
        for item in report.regression.tests
    )

    assert report.regression.tests[0].test_id == "BOLA-001"
    assert report.regression.tests[0].status == "passed"


def test_builder_includes_regression_gate_report(
    sample_findings,
    sample_risk_assessment,
    sample_policy_decision,
    sample_release_gate_decision,
) -> None:
    """Include regression-gate results in the security report."""
    builder = SecurityReportBuilder()

    regression_gate = RegressionGateDecision(
        allowed=False,
        status="failed",
        reason="A security regression test failed.",
        failed_tests=("BOLA-001",),
        errored_tests=(),
        skipped_tests=(),
    )

    report = builder.build(
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
            started_at="2026-09-27T10:00:00+00:00",
            completed_at="2026-09-27T10:05:00+00:00",
        ),
        findings=sample_findings,
        risk=sample_risk_assessment,
        policy=sample_policy_decision,
        decision=sample_release_gate_decision,
        regression_gate=regression_gate,
    )

    assert report.regression_gate is not None
    assert isinstance(
        report.regression_gate,
        RegressionGateReport,
    )

    assert report.regression_gate.allowed is False
    assert report.regression_gate.blocked is True
    assert report.regression_gate.status == "failed"
    assert report.regression_gate.reason == (
        "A security regression test failed."
    )
    assert report.regression_gate.failed_tests == [
        "BOLA-001"
    ]
    assert report.regression_gate.errored_tests == []
    assert report.regression_gate.skipped_tests == []
    assert report.regression_gate.failures == [
        "BOLA-001"
    ]


def test_builder_includes_both_regression_sections(
    sample_findings,
    sample_risk_assessment,
    sample_policy_decision,
    sample_release_gate_decision,
) -> None:
    """Include both regression results and regression-gate results."""
    builder = SecurityReportBuilder()

    regression = RegressionSuiteResult(
        suite_id="securecommerce-regression",
        status=RegressionStatus.FAILED,
        total=1,
        passed=0,
        failed=1,
        errors=0,
        skipped=0,
        results=[
            RegressionResult(
                test_id="BOLA-001",
                status=RegressionStatus.FAILED,
                message="BOLA protection failed.",
            )
        ],
    )

    regression_gate = RegressionGateDecision(
        allowed=False,
        status="failed",
        reason="One or more security regression tests failed.",
        failed_tests=("BOLA-001",),
        errored_tests=(),
        skipped_tests=(),
    )

    report = builder.build(
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
            started_at="2026-09-27T10:00:00+00:00",
            completed_at="2026-09-27T10:05:00+00:00",
        ),
        findings=sample_findings,
        risk=sample_risk_assessment,
        policy=sample_policy_decision,
        decision=sample_release_gate_decision,
        regression=regression,
        regression_gate=regression_gate,
    )

    assert report.regression is not None
    assert report.regression_gate is not None

    assert report.regression.failed == 1
    assert report.regression.tests[0].test_id == "BOLA-001"

    assert report.regression_gate.blocked is True
    assert report.regression_gate.failures == [
        "BOLA-001"
    ]
```
