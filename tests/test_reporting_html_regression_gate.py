from pathlib import Path

from secureforge.reporting import (
    SecurityHTMLReportRenderer,
)


def test_html_renderer_includes_regression_gate(
    sample_security_report,
) -> None:
    """Render regression-gate information in the HTML report."""
    renderer = SecurityHTMLReportRenderer()

    html = renderer.render(sample_security_report)

    gate = sample_security_report.regression_gate

    if gate is None:
        assert "Regression Gate" not in html
        return

    assert "Regression Gate" in html
    assert gate.status in html
    assert gate.reason in html

    if gate.allowed:
        assert "Allowed" in html
    else:
        assert "Blocked" in html


def test_html_renderer_includes_failed_regression_tests(
    sample_security_report,
) -> None:
    """Render failed regression identifiers."""
    renderer = SecurityHTMLReportRenderer()

    html = renderer.render(sample_security_report)

    gate = sample_security_report.regression_gate

    if gate is None:
        return

    for test_id in gate.failed_tests:
        assert test_id in html

    for test_id in gate.errored_tests:
        assert test_id in html

    for test_id in gate.skipped_tests:
        assert test_id in html


def test_html_renderer_escapes_regression_gate_content(
    sample_security_report,
) -> None:
    """HTML-escape untrusted regression-gate values."""
    from secureforge.reporting import (
        RegressionGateReport,
        SecurityReport,
    )

    gate = RegressionGateReport(
        allowed=False,
        blocked=True,
        status="failed",
        reason="<script>alert('xss')</script>",
        failed_tests=[
            "<img src=x onerror=alert(1)>"
        ],
        errored_tests=[],
        skipped_tests=[],
        failures=[
            "<svg onload=alert(1)>"
        ],
    )

    report = SecurityReport(
        release=sample_security_report.release,
        scan=sample_security_report.scan,
        findings=sample_security_report.findings,
        risk=sample_security_report.risk,
        policy=sample_security_report.policy,
        decision=sample_security_report.decision,
        remediation=sample_security_report.remediation,
        regression=sample_security_report.regression,
        regression_gate=gate,
        generated_at=sample_security_report.generated_at,
    )

    renderer = SecurityHTMLReportRenderer()

    html = renderer.render(report)

    assert "<script>alert('xss')</script>" not in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert "<svg onload=alert(1)>" not in html

    assert "&lt;script&gt;" in html
    assert "&lt;img" in html
    assert "&lt;svg" in html


def test_html_renderer_writes_regression_gate_report(
    sample_security_report,
    tmp_path: Path,
) -> None:
    """Write an HTML report containing regression-gate evidence."""
    renderer = SecurityHTMLReportRenderer()

    output_path = tmp_path / "security-report.html"

    renderer.write_html(
        sample_security_report,
        output_path,
    )

    assert output_path.is_file()

    html = output_path.read_text(encoding="utf-8")

    if sample_security_report.regression_gate is not None:
        assert "Regression Gate" in html
