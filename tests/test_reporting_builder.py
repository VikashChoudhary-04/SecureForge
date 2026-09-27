```python id="q7m2x4"
"""Tests for the SecureForge security report builder."""

from secureforge.reporting import (
    DecisionReport,
    PolicyReport,
    RegressionGateReport,
    RegressionReport,
    ReleaseMetadata,
    RemediationReport,
    ReportFinding,
    RiskReport,
    ScanMetadata,
    SecurityReportBuilder,
)


def test_build_security_report(
    sample_findings,
    sample_risk_assessment,
    sample_policy_decision,
    sample_release_gate_decision,
) -> None:
    """Build a complete security report from domain objects."""
    builder = SecurityReportBuilder()

    release = ReleaseMetadata(
        application="securecommerce",
        version="1.0.0",
        commit_sha="abc123",
        environment="test",
    )

    scan = ScanMetadata(
        scan_id="scan-001",
        profile="standard",
        target="http://localhost:5000",
        started_at="2026-09-27T10:00:00+00:00",
        completed_at="2026-09-27T10:05:00+00:00",
    )

    report = builder.build(
        release=release,
        scan=scan,
        findings=sample_findings,
        risk=sample_risk_assessment,
        policy=sample_policy_decision,
        decision=sample_release_gate_decision,
    )

    assert isinstance(report.release, ReleaseMetadata)
    assert isinstance(report.scan, ScanMetadata)
    assert isinstance(report.risk, RiskReport)
    assert isinstance(report.policy, PolicyReport)
    assert isinstance(report.decision, DecisionReport)
    assert isinstance(report.remediation, RemediationReport)

    assert report.release == release
    assert report.scan == scan

    assert len(report.findings) == len(
        sample_findings
    )

    assert report.risk.score == (
        sample_risk_assessment.score
    )

    assert report.policy.policy_name == (
        sample_policy_decision.policy_name
    )

    assert report.decision.release_allowed == (
        sample_release_gate_decision.release_allowed
    )


def test_build_security_report_maps_findings(
    sample_findings,
    sample_risk_assessment,
    sample_policy_decision,
    sample_release_gate_decision,
) -> None:
    """Map normalized findings into report findings."""
    builder = SecurityReportBuilder()

    release = ReleaseMetadata(
        application="securecommerce",
        version="1.0.0",
        commit_sha="abc123",
        environment="test",
    )

    scan = ScanMetadata(
        scan_id="scan-001",
        profile="standard",
        target="http://localhost:5000",
        started_at="2026-09-27T10:00:00+00:00",
        completed_at="2026-09-27T10:05:00+00:00",
    )

    report = builder.build(
        release=release,
        scan=scan,
        findings=sample_findings,
        risk=sample_risk_assessment,
        policy=sample_policy_decision,
        decision=sample_release_gate_decision,
    )

    for source, rendered in zip(
        sample_findings,
        report.findings,
    ):
        assert isinstance(
            rendered,
            ReportFinding,
        )

        assert rendered.finding_id == source.finding_id
        assert rendered.title == source.title
        assert rendered.source == source.source
        assert rendered.asset == source.asset
        assert rendered.application == source.application
        assert rendered.endpoint == source.endpoint
        assert rendered.parameter == source.parameter
        assert rendered.cwe == source.cwe
        assert rendered.owasp_mapping == source.owasp_mapping
        assert (
            rendered.security_requirement
            == source.security_requirement
        )
        assert rendered.severity == source.severity.value
        assert rendered.confidence == source.confidence.value
        assert rendered.description == source.description
        assert rendered.impact == source.impact
        assert rendered.remediation == source.remediation
        assert rendered.status == source.status.value
        assert (
            rendered.validation_status
            == source.validation_status.value
        )
        assert rendered.regression_test == (
            source.regression_test
        )
        assert rendered.correlation_ids == (
            source.correlation_ids
        )


def test_build_security_report_calculates_remediation(
    sample_findings,
    sample_risk_assessment,
    sample_policy_decision,
    sample_release_gate_decision,
) -> None:
    """Calculate remediation counts from finding lifecycle state."""
    builder = SecurityReportBuilder()

    release = ReleaseMetadata(
        application="securecommerce",
        version="1.0.0",
        commit_sha="abc123",
        environment="test",
    )

    scan = ScanMetadata(
        scan_id="scan-001",
        profile="standard",
        target="http://localhost:5000",
        started_at="2026-09-27T10:00:00+00:00",
        completed_at="2026-09-27T10:05:00+00:00",
    )

    report = builder.build(
        release=release,
        scan=scan,
        findings=sample_findings,
        risk=sample_risk_assessment,
        policy=sample_policy_decision,
        decision=sample_release_gate_decision,
    )

    expected_open = sum(
        1
        for finding in sample_findings
        if finding.status.value == "open"
    )

    expected_remediated = sum(
        1
        for finding in sample_findings
        if finding.status.value == "remediated"
    )

    expected_verified = sum(
        1
        for finding in sample_findings
        if finding.validation_status.value == "verified"
    )

    assert report.remediation.total == len(
        sample_findings
    )

    assert report.remediation.open == expected_open
    assert report.remediation.remediated == expected_remediated
    assert report.remediation.verified == expected_verified


def test_build_security_report_without_optional_sections(
    sample_findings,
    sample_risk_assessment,
    sample_policy_decision,
    sample_release_gate_decision,
) -> None:
    """Optional regression sections are absent when not supplied."""
    builder = SecurityReportBuilder()

    release = ReleaseMetadata(
        application="securecommerce",
        version="1.0.0",
        commit_sha="abc123",
        environment="test",
    )

    scan = ScanMetadata(
        scan_id="scan-001",
        profile="quick",
        target="http://localhost:5000",
        started_at="2026-09-27T10:00:00+00:00",
        completed_at="2026-09-27T10:05:00+00:00",
    )

    report = builder.build(
        release=release,
        scan=scan,
        findings=sample_findings,
        risk=sample_risk_assessment,
        policy=sample_policy_decision,
        decision=sample_release_gate_decision,
    )

    assert isinstance(report, SecurityReport)
    assert report.regression is not None
    assert report.regression_gate is None


def test_report_models_are_serializable(
    sample_findings,
    sample_risk_assessment,
    sample_policy_decision,
    sample_release_gate_decision,
) -> None:
    """The generated report must be serializable through Pydantic."""
    builder = SecurityReportBuilder()

    release = ReleaseMetadata(
        application="securecommerce",
        version="1.0.0",
        commit_sha="abc123",
        environment="test",
    )

    scan = ScanMetadata(
        scan_id="scan-001",
        profile="standard",
        target="http://localhost:5000",
        started_at="2026-09-27T10:00:00+00:00",
        completed_at="2026-09-27T10:05:00+00:00",
    )

    report = builder.build(
        release=release,
        scan=scan,
        findings=sample_findings,
        risk=sample_risk_assessment,
        policy=sample_policy_decision,
        decision=sample_release_gate_decision,
    )

    payload = report.model_dump(
        mode="json"
    )

    assert isinstance(payload, dict)
    assert payload["release"]["application"] == "securecommerce"
    assert payload["scan"]["scan_id"] == "scan-001"
    assert "findings" in payload
    assert "risk" in payload
    assert "policy" in payload
    assert "decision" in payload
    assert "remediation" in payload
```
