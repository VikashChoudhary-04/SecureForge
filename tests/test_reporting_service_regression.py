```python id="5p4m7c"
"""Tests for regression-aware security reporting services."""

from secureforge.reporting import (
    ReleaseMetadata,
    ScanMetadata,
    SecurityReportService,
)
from secureforge.regression import (
    RegressionResult,
    RegressionStatus,
    RegressionSuiteResult,
)


def test_service_build_report_with_regression(
    sample_findings,
    sample_risk_assessment,
    sample_policy_decision,
    sample_release_gate_decision,
) -> None:
    """Build a report through the service with regression results."""
    service = SecurityReportService()

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
        regression=regression,
    )

    assert report.regression is not None
    assert report.regression.suite_id == (
        "securecommerce-regression"
    )
    assert report.regression.status == "passed"
    assert report.regression.total == 2
    assert report.regression.passed == 2
    assert report.regression.failed == 0
    assert len(report.regression.tests) == 2


def test_service_build_report_with_failed_regression(
    sample_findings,
    sample_risk_assessment,
    sample_policy_decision,
    sample_release_gate_decision,
) -> None:
    """Build a report containing failed regression evidence."""
    service = SecurityReportService()

    regression = RegressionSuiteResult(
        suite_id="securecommerce-regression",
        status=RegressionStatus.FAILED,
        total=2,
        passed=1,
        failed=1,
        errors=0,
        skipped=0,
        results=[
            RegressionResult(
                test_id="BOLA-001",
                status=RegressionStatus.FAILED,
                message="BOLA protection failed.",
            ),
            RegressionResult(
                test_id="SQLI-001",
                status=RegressionStatus.PASSED,
                message="SQL injection protection verified.",
            ),
        ],
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
        regression=regression,
    )

    assert report.regression is not None
    assert report.regression.status == "failed"
    assert report.regression.failed == 1

    failed_tests = [
        test
        for test in report.regression.tests
        if test.status == "failed"
    ]

    assert len(failed_tests) == 1
    assert failed_tests[0].test_id == "BOLA-001"


def test_service_generate_from_results_with_regression(
    sample_findings,
    sample_risk_assessment,
    sample_policy_decision,
    sample_release_gate_decision,
    tmp_path,
) -> None:
    """Generate report files from domain results with regression data."""
    from secureforge.reporting import ReportPaths

    service = SecurityReportService()

    regression = RegressionSuiteResult(
        suite_id="securecommerce-regression",
        status=RegressionStatus.PASSED,
        total=1,
        passed=1,
        failed=0,
        errors=0,
        skipped=0,
        results=[
            RegressionResult(
                test_id="BOLA-001",
                status=RegressionStatus.PASSED,
                message="BOLA protection verified.",
            )
        ],
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
        regression=regression,
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

    assert "securecommerce-regression" in json_content
    assert "BOLA-001" in json_content

    assert "Regression Testing" in html_content
    assert "securecommerce-regression" in html_content
    assert "BOLA-001" in html_content
```

**Next file: `tests/test_reporting_service_regression_gate.py`**
