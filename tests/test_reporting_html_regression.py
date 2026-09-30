"""Tests for regression rendering in SecureForge HTML reports."""

from __future__ import annotations

from secureforge.regression import (
    RegressionResult,
    RegressionStatus,
    RegressionSuiteResult,
)
from secureforge.reporting.html import (
    SecurityHTMLReportRenderer,
)
from secureforge.reporting.regression import (
    build_regression_report,
)


def build_report(
    status: RegressionStatus = RegressionStatus.FAILED,
):
    """Build a regression report for HTML rendering tests."""
    result = RegressionSuiteResult(
        suite_id="securecommerce-regression",
        name="SecureCommerce Regression Suite",
        status=status,
        results=[
            RegressionResult(
                test_id="BOLA-001",
                security_requirement="SF-AUTHZ-001",
                status=RegressionStatus.FAILED,
                expected="HTTP 403",
                actual="HTTP 200",
                message="Cross-user access remains possible.",
                evidence={
                    "status_code": 200,
                    "endpoint": "/api/orders/2",
                },
                started_at=(
                    "2026-09-27T10:00:00+00:00"
                ),
                completed_at=(
                    "2026-09-27T10:00:01+00:00"
                ),
                duration_seconds=1.0,
            ),
            RegressionResult(
                test_id="SQLI-001",
                security_requirement="SF-INPUT-001",
                status=RegressionStatus.PASSED,
                expected="Rejected",
                actual="Rejected",
                message="SQL injection input was safely rejected.",
                evidence={
                    "status_code": 400,
                },
                started_at=(
                    "2026-09-27T10:00:01+00:00"
                ),
                completed_at=(
                    "2026-09-27T10:00:02+00:00"
                ),
                duration_seconds=1.0,
            ),
        ],
        started_at="2026-09-27T10:00:00+00:00",
        completed_at="2026-09-27T10:00:02+00:00",
        duration_seconds=2.0,
    )

    return build_regression_report(
        result
    )


def test_html_contains_regression_section(
    sample_security_report,
):
    """HTML should contain the regression section."""
    sample_security_report.regression = (
        build_report()
    )

    renderer = SecurityHTMLReportRenderer()

    html = renderer.render(
        sample_security_report
    )

    assert "<h2>Regression Testing</h2>" in html
    assert "SecureCommerce Regression Suite" in html
    assert "BOLA-001" in html
    assert "SQLI-001" in html
    assert "failed" in html
    assert "passed" in html


def test_html_contains_regression_summary(
    sample_security_report,
):
    """HTML should display regression summary metrics."""
    sample_security_report.regression = (
        build_report()
    )

    renderer = SecurityHTMLReportRenderer()

    html = renderer.render(
        sample_security_report
    )

    assert "Total" in html
    assert "Passed" in html
    assert "Failed" in html
    assert "Errors" in html
    assert "Skipped" in html


def test_html_contains_regression_expected_and_actual(
    sample_security_report,
):
    """HTML should show expected and actual regression outcomes."""
    sample_security_report.regression = (
        build_report()
    )

    renderer = SecurityHTMLReportRenderer()

    html = renderer.render(
        sample_security_report
    )

    assert "HTTP 403" in html
    assert "HTTP 200" in html
    assert "Cross-user access remains possible." in html
    assert (
        "SQL injection input was safely rejected."
        in html
    )


def test_html_renders_regression_evidence(
    sample_security_report,
):
    """Regression evidence should be visible in the report."""
    sample_security_report.regression = (
        build_report()
    )

    renderer = SecurityHTMLReportRenderer()

    html = renderer.render(
        sample_security_report
    )

    assert "status_code" in html
    assert "/api/orders/2" in html


def test_html_escapes_regression_evidence(
    sample_security_report,
):
    """Untrusted regression evidence should be HTML escaped."""
    sample_security_report.regression = (
        build_report()
    )

    sample_security_report.regression.tests[
        0
    ].evidence = {
        "payload": (
            "<script>"
            "alert('xss')"
            "</script>"
        ),
    }

    renderer = SecurityHTMLReportRenderer()

    html = renderer.render(
        sample_security_report
    )

    assert "<script>alert('xss')</script>" not in html
    assert (
        "&lt;script&gt;"
        in html
    )


def test_html_handles_no_regression_tests(
    sample_security_report,
):
    """HTML should clearly indicate when regressions were not run."""
    sample_security_report.regression = (
        build_report(
            status=RegressionStatus.SKIPPED
        )
    )

    sample_security_report.regression.tests = []

    renderer = SecurityHTMLReportRenderer()

    html = renderer.render(
        sample_security_report
    )

    assert "No regression tests were executed." in html
    assert "securecommerce-regression" in html


def test_html_write_html_persists_regression_report(
    sample_security_report,
    tmp_path,
):
    """HTML writer should persist regression information."""
    sample_security_report.regression = (
        build_report()
    )

    output = (
        tmp_path
        / "security-report.html"
    )

    renderer = SecurityHTMLReportRenderer()

    result = renderer.write_html(
        sample_security_report,
        output,
    )

    assert result == output
    assert output.is_file()

    content = output.read_text(
        encoding="utf-8"
    )

    assert "Regression Testing" in content
    assert "BOLA-001" in content
    assert "SecureCommerce Regression Suite" in content
