"""Tests for regression-gate handling in the reporting service."""

from secureforge.reporting import (
    ReleaseMetadata,
    ScanMetadata,
    SecurityReportService,
)
from secureforge.regression import RegressionGateDecision


def test_service_build_report_with_allowed_regression_gate(
    sample_findings,
    sample_risk_assessment,
    sample_policy_decision,
    sample_release_gate_decision,
) -> None:
    """Build a report with an allowed regression gate."""
    service = SecurityReportService()

    gate = RegressionGateDecision(
        allowed=True,
        status="passed",
        reason="All executed security regression tests passed.",
        failed_tests=(),
        errored_tests=(),
        skipped_tests=(),
    )

    report = service.build_report(
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


def test_service_build_report_with_failed_regression_gate(
    sample_findings,
    sample_risk_assessment,
    sample_policy_decision,
    sample_release_gate_decision,
) -> None:
    """Build a report with a failed regression gate."""
    service = SecurityReportService()

    gate = RegressionGateDecision(
        allowed=False,
        status="failed",
        reason="One or more security regression tests failed.",
        failed_tests=("BOLA-001",),
        errored_tests=(),
        skipped_tests=("XSS-001",),
    )

    report = service.build_report(
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
        "BOLA-001"
    ]

    assert report.regression_gate.errored_tests == []
    assert report.regression_gate.skipped_tests == [
        "XSS-001"
    ]

    assert report.regression_gate.failures == [
        "BOLA-001"
    ]


def test_service_generate_from_results_with_regression_gate(
    sample_findings,
    sample_risk_assessment,
    sample_policy_decision,
    sample_release_gate_decision,
    tmp_path,
) -> None:
    """Generate report files containing regression-gate evidence."""
    from secureforge.reporting import ReportPaths

    service = SecurityReportService()

    gate = RegressionGateDecision(
        allowed=False,
        status="failed",
        reason="One or more security regression tests failed.",
        failed_tests=("BOLA-001",),
        errored_tests=(),
        skipped_tests=(),
    )

    paths = ReportPaths(
        json_path=tmp_path / "security-report.json",
        html_path=tmp_path / "security-report.html",
    )

    generated = service.generate_from_results(
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
        paths=paths,
        regression_gate=gate,
    )

    assert generated == paths
    assert paths.json_path.is_file()
    assert paths.html_path.is_file()

    json_content = paths.json_path.read_text(
        encoding="utf-8"
    )

    html_content = paths.html_path.read_text(
        encoding="utf-8"
    )

    assert '"regression_gate"' in json_content
    assert '"allowed": false' in json_content
    assert "BOLA-001" in json_content

    assert "Regression Gate" in html_content
    assert "BOLA-001" in html_content
    assert "blocked" in html_content.lower()
