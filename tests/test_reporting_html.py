"""Tests for SecureForge HTML security reports."""

from __future__ import annotations

from secureforge.core.findings import (
    Confidence,
    Finding,
    Severity,
)
from secureforge.core.policy import PolicyDecision
from secureforge.core.release_gate import (
    ReleaseGateDecision,
    ReleaseGateStatus,
)
from secureforge.core.risk import RiskAssessment
from secureforge.reporting import (
    SecurityHTMLReportRenderer,
    SecurityReportBuilder,
)


def build_report():
    """Build a representative report for HTML rendering."""
    finding = Finding(
        finding_id="SF-XSS-001",
        title="Reflected XSS <script>",
        source="dast",
        source_finding_id="DAST-XSS-001",
        application="SecureCommerce",
        asset="SecureCommerce Web Application",
        endpoint="/vulnerable/search",
        parameter="query",
        cwe="CWE-79",
        owasp="A05:2025-Injection",
        security_requirement="SF-INPUT-001",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        description=(
            "User-controlled input is reflected "
            "without contextual output encoding."
        ),
        impact="Attacker-controlled script may execute in a victim browser.",
        remediation="Apply context-aware output encoding.",
    )

    risk = RiskAssessment(
        score=7.5,
        highest_severity="high",
        confirmed_critical=0,
        confirmed_high=1,
        factors={
            "internet_exposure": True,
            "sensitive_data": False,
            "exploit_evidence": True,
        },
    )

    policy = PolicyDecision(
        policy_name="default",
        actions={
            "critical": "block",
            "high": "block",
            "medium": "review",
            "low": "pass",
            "info": "pass",
        },
        tool_errors=[],
        regression_failures=[],
        exceptions=[],
    )

    release_gate = ReleaseGateDecision(
        status=ReleaseGateStatus.BLOCK,
        reason="Confirmed high-severity XSS finding.",
        release_allowed=False,
    )

    return SecurityReportBuilder().build(
        release_id="release-html-001",
        application="SecureCommerce",
        version="0.1.0",
        environment="lab",
        profile="standard",
        scan_id="SF-SCAN-HTML-001",
        scan_status="completed",
        integrations=["dast"],
        findings=[finding],
        risk=risk,
        policy=policy,
        release_gate=release_gate,
        regression_results=[
            {
                "test_id": "XSS-001",
                "requirement": "SF-INPUT-001",
                "status": "failed",
                "expected_result": "Input is encoded.",
                "actual_result": "Input is reflected.",
                "message": "XSS regression remains.",
            }
        ],
    )


def test_html_renderer_returns_standalone_document():
    """Renderer should return a complete HTML document."""
    report = build_report()

    renderer = SecurityHTMLReportRenderer()

    html = renderer.render(report)

    assert html.startswith("<!DOCTYPE html>")
    assert "<html" in html
    assert "<head>" in html
    assert "<body>" in html
    assert "</html>" in html


def test_html_contains_release_information():
    """HTML should expose important release metadata."""
    report = build_report()

    html = SecurityHTMLReportRenderer().render(report)

    assert "SecureCommerce" in html
    assert "release-html-001" in html
    assert "0.1.0" in html
    assert "standard" in html


def test_html_contains_release_decision():
    """HTML should clearly display the release decision."""
    report = build_report()

    html = SecurityHTMLReportRenderer().render(report)

    assert "Release Decision" in html
    assert "block" in html
    assert "Release allowed:" in html
    assert "False" in html


def test_html_contains_finding_information():
    """HTML should display normalized finding information."""
    report = build_report()

    html = SecurityHTMLReportRenderer().render(report)

    assert "SF-XSS-001" in html
    assert "CWE-79" not in html
    assert "high" in html
    assert "dast" in html
    assert "/vulnerable/search" in html
    assert "SF-INPUT-001" in html


def test_html_escapes_untrusted_finding_content():
    """Finding content should be HTML escaped."""
    report = build_report()

    html = SecurityHTMLReportRenderer().render(report)

    assert "Reflected XSS &lt;script&gt;" in html
    assert "<script>" not in html


def test_html_contains_regression_results():
    """HTML should display regression test results."""
    report = build_report()

    html = SecurityHTMLReportRenderer().render(report)

    assert "Regression Testing" in html
    assert "XSS-001" in html
    assert "failed" in html
    assert "XSS regression remains." in html


def test_html_contains_policy_information():
    """HTML should display policy actions."""
    report = build_report()

    html = SecurityHTMLReportRenderer().render(report)

    assert "Policy Evaluation" in html
    assert "default" in html
    assert "Critical" in html
    assert "High" in html
    assert "Medium" in html
    assert "Low" in html


def test_html_writer_creates_file(tmp_path):
    """Renderer should write a standalone HTML report."""
    report = build_report()

    output_path = tmp_path / "reports" / "security-report.html"

    result = SecurityHTMLReportRenderer().write_html(
        report,
        output_path,
    )

    assert result == output_path
    assert output_path.is_file()

    content = output_path.read_text(encoding="utf-8")

    assert content.startswith("<!DOCTYPE html>")
    assert "SecureForge Security Report" in content
    assert "SF-XSS-001" in content
