"""Tests for scan-to-report conversion."""

from secureforge.reporting import (
    build_scan_report,
)


def test_build_scan_report(
    sample_scan_result,
) -> None:
    """Build a complete report from a security scan."""
    from secureforge.reporting import (
        ReleaseMetadata,
        ScanMetadata,
    )

    release = ReleaseMetadata(
        application="securecommerce",
        version="1.0.0",
        commit_sha="abc123",
        environment="test",
    )

    scan = ScanMetadata(
        scan_id=sample_scan_result.execution.scan_id,
        profile=sample_scan_result.execution.profile,
        target=sample_scan_result.execution.target,
        started_at=sample_scan_result.execution.started_at,
        completed_at=sample_scan_result.execution.completed_at,
    )

    report = build_scan_report(
        sample_scan_result,
        release=release,
        scan=scan,
    )

    assert report.release == release
    assert report.scan == scan

    assert len(report.findings) == len(
        sample_scan_result.findings
    )

    assert report.risk.score == (
        sample_scan_result.pipeline.risk.score
    )

    assert report.risk.highest_severity == (
        sample_scan_result.pipeline.risk.highest_severity.value
    )

    assert report.risk.finding_count == (
        sample_scan_result.pipeline.risk.finding_count
    )

    assert report.policy.policy_name == (
        sample_scan_result.pipeline.policy.policy_name
    )

    assert report.policy.action == (
        sample_scan_result.pipeline.policy.action
    )

    assert report.policy.allowed == (
        sample_scan_result.pipeline.policy.allowed
    )

    assert report.decision.release_allowed == (
        sample_scan_result.pipeline.release_gate.release_allowed
    )

    assert report.decision.status == (
        sample_scan_result.pipeline.release_gate.status.value
    )

    assert report.decision.reason == (
        sample_scan_result.pipeline.release_gate.reason
    )

    assert report.remediation.total == len(
        sample_scan_result.findings
    )


def test_build_scan_report_preserves_finding_metadata(
    sample_scan_result,
) -> None:
    """Preserve normalized finding metadata in the report."""
    from secureforge.reporting import (
        ReleaseMetadata,
        ScanMetadata,
    )

    release = ReleaseMetadata(
        application="securecommerce",
        version="1.0.0",
        commit_sha="abc123",
        environment="test",
    )

    scan = ScanMetadata(
        scan_id=sample_scan_result.execution.scan_id,
        profile=sample_scan_result.execution.profile,
        target=sample_scan_result.execution.target,
        started_at=sample_scan_result.execution.started_at,
        completed_at=sample_scan_result.execution.completed_at,
    )

    report = build_scan_report(
        sample_scan_result,
        release=release,
        scan=scan,
    )

    source_findings = sample_scan_result.findings

    assert len(report.findings) == len(
        source_findings
    )

    for source, rendered in zip(
        source_findings,
        report.findings,
    ):
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


def test_build_scan_report_preserves_evidence(
    sample_scan_result,
) -> None:
    """Preserve finding evidence when building the report."""
    from secureforge.reporting import (
        ReleaseMetadata,
        ScanMetadata,
    )

    release = ReleaseMetadata(
        application="securecommerce",
        version="1.0.0",
        commit_sha="abc123",
        environment="test",
    )

    scan = ScanMetadata(
        scan_id=sample_scan_result.execution.scan_id,
        profile=sample_scan_result.execution.profile,
        target=sample_scan_result.execution.target,
        started_at=sample_scan_result.execution.started_at,
        completed_at=sample_scan_result.execution.completed_at,
    )

    report = build_scan_report(
        sample_scan_result,
        release=release,
        scan=scan,
    )

    for source, rendered in zip(
        sample_scan_result.findings,
        report.findings,
    ):
        assert len(rendered.evidence) == len(
            source.evidence
        )

        for source_evidence, rendered_evidence in zip(
            source.evidence,
            rendered.evidence,
        ):
            assert rendered_evidence == (
                source_evidence.model_dump(
                    mode="json"
                )
            )


def test_build_scan_report_preserves_regression_results(
    sample_scan_result,
) -> None:
    """Preserve regression-suite results when available."""
    from secureforge.reporting import (
        ReleaseMetadata,
        ScanMetadata,
    )

    regression = sample_scan_result.pipeline.regression

    if regression is None:
        return

    release = ReleaseMetadata(
        application="securecommerce",
        version="1.0.0",
        commit_sha="abc123",
        environment="test",
    )

    scan = ScanMetadata(
        scan_id=sample_scan_result.execution.scan_id,
        profile=sample_scan_result.execution.profile,
        target=sample_scan_result.execution.target,
        started_at=sample_scan_result.execution.started_at,
        completed_at=sample_scan_result.execution.completed_at,
    )

    report = build_scan_report(
        sample_scan_result,
        release=release,
        scan=scan,
    )

    assert report.regression is not None
    assert report.regression.suite_id == regression.suite_id
    assert report.regression.status == regression.status.value
    assert report.regression.total == regression.total
    assert report.regression.passed == regression.passed
    assert report.regression.failed == regression.failed
    assert report.regression.errors == regression.errors
    assert report.regression.skipped == regression.skipped
    assert len(report.regression.tests) == len(
        regression.results
    )

    for source, rendered in zip(
        regression.results,
        report.regression.tests,
    ):
        assert rendered.test_id == source.test_id
        assert rendered.status == source.status.value
        assert rendered.message == source.message


def test_build_scan_report_preserves_regression_gate(
    sample_scan_result,
) -> None:
    """Preserve regression-gate results when available."""
    from secureforge.reporting import (
        ReleaseMetadata,
        ScanMetadata,
    )

    gate = sample_scan_result.pipeline.regression_gate

    if gate is None:
        return

    release = ReleaseMetadata(
        application="securecommerce",
        version="1.0.0",
        commit_sha="abc123",
        environment="test",
    )

    scan = ScanMetadata(
        scan_id=sample_scan_result.execution.scan_id,
        profile=sample_scan_result.execution.profile,
        target=sample_scan_result.execution.target,
        started_at=sample_scan_result.execution.started_at,
        completed_at=sample_scan_result.execution.completed_at,
    )

    report = build_scan_report(
        sample_scan_result,
        release=release,
        scan=scan,
    )

    assert report.regression_gate is not None
    assert report.regression_gate.allowed == gate.allowed
    assert report.regression_gate.blocked == gate.blocked
    assert report.regression_gate.status == gate.status
    assert report.regression_gate.reason == gate.reason
    assert (
        report.regression_gate.failed_tests
        == list(gate.failed_tests)
    )
    assert (
        report.regression_gate.errored_tests
        == list(gate.errored_tests)
    )
    assert (
        report.regression_gate.skipped_tests
        == list(gate.skipped_tests)
    )
    assert (
        report.regression_gate.failures
        == list(gate.failures)
    )
