```python id="s4n8c2"
"""Tests for regression-gate handling in the report builder."""

from secureforge.reporting import (
    RegressionGateReport,
    ReleaseMetadata,
    ScanMetadata,
    SecurityReportBuilder,
)
from secureforge.regression import RegressionGateDecision


def test_builder_maps_allowed_regression_gate(
    sample_findings,
    sample_risk_assessment,
    sample_policy_decision,
    sample_release_gate_decision,
) -> None:
    """Map an allowed regression gate into the report."""
    builder = SecurityReportBuilder()

    gate = RegressionGateDecision(
        allowed=True,
        status="passed",
        reason="All executed security regression tests passed.",
        failed_tests=(),
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
        regression_gate=gate,
    )

    assert report.regression_gate is not None
    assert isinstance(
        report.regression_gate,
        RegressionGateReport,
    )

    assert report.regression_gate.allowed is True
    assert report.regression_gate.blocked is False
    assert report.regression_gate.status == "passed"
    assert report.regression_gate.reason == (
        "All executed security regression tests passed."
    )
    assert report.regression_gate.failed_tests == []
    assert report.regression_gate.errored_tests == []
    assert report.regression_gate.skipped_tests == []
    assert report.regression_gate.failures == []


def test_builder_maps_failed_regression_gate(
    sample_findings,
    sample_risk_assessment,
    sample_policy_decision,
    sample_release_gate_decision,
) -> None:
    """Map a failed regression gate into the report."""
    builder = SecurityReportBuilder()

    gate = RegressionGateDecision(
        allowed=False,
        status="failed",
        reason="One or more security regression tests failed.",
        failed_tests=("BOLA-001", "SQLI-001"),
        errored_tests=(),
        skipped_tests=("XSS-001",),
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
        regression_gate=gate,
    )

    assert report.regression_gate is not None
    assert report.regression_gate.allowed is False
    assert report.regression_gate.blocked is True
    assert report.regression_gate.status == "failed"

    assert report.regression_gate.failed_tests == [
        "BOLA-001",
        "SQLI-001",
    ]

    assert report.regression_gate.errored_tests == []
    assert report.regression_gate.skipped_tests == [
        "XSS-001"
    ]

    assert report.regression_gate.failures == [
        "BOLA-001",
        "SQLI-001",
    ]


def test_builder_maps_error_regression_gate(
    sample_findings,
    sample_risk_assessment,
    sample_policy_decision,
    sample_release_gate_decision,
) -> None:
    """Map a regression-gate execution error into the report."""
    builder = SecurityReportBuilder()

    gate = RegressionGateDecision(
        allowed=False,
        status="error",
        reason="One or more security regression tests could not be executed.",
        failed_tests=(),
        errored_tests=("AUTHZ-001",),
        skipped_tests=("XSS-001",),
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
        regression_gate=gate,
    )

    assert report.regression_gate is not None
    assert report.regression_gate.allowed is False
    assert report.regression_gate.blocked is True
    assert report.regression_gate.status == "error"

    assert report.regression_gate.failed_tests == []
    assert report.regression_gate.errored_tests == [
        "AUTHZ-001"
    ]
    assert report.regression_gate.skipped_tests == [
        "XSS-001"
    ]

    assert report.regression_gate.failures == [
        "AUTHZ-001"
    ]
```
