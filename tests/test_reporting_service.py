"""Tests for the SecureForge reporting service."""

from __future__ import annotations

import json

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
    SecurityReportBuilder,
    SecurityReportService,
)


def build_report():
    """Build a representative security report."""
    finding = Finding(
        finding_id="SF-AUTHZ-001",
        title="Broken Function-Level Authorization",
        source="api",
        source_finding_id="API-AUTHZ-001",
        application="SecureCommerce",
        asset="SecureCommerce API",
        endpoint="/api/admin/users",
        cwe="CWE-285",
        owasp="API5:2023-Broken Function Level Authorization",
        security_requirement="SF-AUTHZ-002",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        description=(
            "A non-administrative user can access "
            "an administrative API function."
        ),
        impact=(
            "Unauthorized users may perform "
            "privileged administrative operations."
        ),
        remediation=(
            "Enforce server-side role authorization "
            "for administrative functions."
        ),
    )

    risk = RiskAssessment(
        score=8.0,
        highest_severity="high",
        confirmed_critical=0,
        confirmed_high=1,
        factors={
            "internet_exposure": True,
            "sensitive_data": True,
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
        reason=(
            "Confirmed high-severity authorization "
            "finding violates release policy."
        ),
        release_allowed=False,
    )

    return SecurityReportBuilder().build(
        release_id="release-service-001",
        application="SecureCommerce",
        version="0.1.0",
        environment="lab",
        profile="standard",
        scan_id="SF-SCAN-SERVICE-001",
        scan_status="completed",
        integrations=["api"],
        findings=[finding],
        risk=risk,
        policy=policy,
        release_gate=release_gate,
    )


def test_reporting_service_generates_json_and_html(
    tmp_path,
):
    """Reporting service should generate both report formats."""
    report = build_report()

    json_path = (
        tmp_path
        / "reports"
        / "security-report.json"
    )

    html_path = (
        tmp_path
        / "reports"
        / "security-report.html"
    )

    service = SecurityReportService()

    paths = service.generate(
        report,
        json_path=json_path,
        html_path=html_path,
    )

    assert paths.json_path == json_path
    assert paths.html_path == html_path

    assert json_path.is_file()
    assert html_path.is_file()


def test_generated_json_contains_release_decision(
    tmp_path,
):
    """Generated JSON should preserve the final release decision."""
    report = build_report()

    json_path = (
        tmp_path
        / "security-report.json"
    )

    html_path = (
        tmp_path
        / "security-report.html"
    )

    SecurityReportService().generate(
        report,
        json_path=json_path,
        html_path=html_path,
    )

    data = json.loads(
        json_path.read_text(
            encoding="utf-8"
        )
    )

    assert data["release"]["release_id"] == (
        "release-service-001"
    )
    assert data["decision"]["status"] == "block"
    assert data["decision"]["release_allowed"] is False


def test_generated_html_contains_finding_and_decision(
    tmp_path,
):
    """Generated HTML should preserve important report information."""
    report = build_report()

    json_path = (
        tmp_path
        / "security-report.json"
    )

    html_path = (
        tmp_path
        / "security-report.html"
    )

    SecurityReportService().generate(
        report,
        json_path=json_path,
        html_path=html_path,
    )

    html = html_path.read_text(
        encoding="utf-8"
    )

    assert "SecureCommerce" in html
    assert "SF-AUTHZ-001" in html
    assert "block" in html
    assert "Release allowed:" in html
