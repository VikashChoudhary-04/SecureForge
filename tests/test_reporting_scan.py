```python id="b5n8qx"
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
        release_id="release-001",
        application="securecommerce",
        version="1.0.0",
        commit_sha="abc123",
        environment="lab",
        timestamp=(
            "2026-09-27T10:01:00+00:00"
        ),
    )

    scan = ScanMetadata(
        scan_id="scan-001",
        profile="standard",
        status="completed",
        tools=["dast"],
        started_at=(
            "2026-09-27T10:00:00+00:00"
        ),
        completed_at=(
            "2026-09-27T10:01:00+00:00"
        ),
        duration_seconds=60.0,
    )

    report = build_scan_report(
        sample_scan_result,
        release=release,
        scan=scan,
    )

    assert (
        report.release
        == release
    )

    assert (
        report.scan
        == scan
    )

    assert len(
        report.findings
    ) == len(
        sample_scan_result.findings
    )

    assert (
        report.risk.score
        == sample_scan_result.pipeline.risk.score
    )

    assert (
        report.policy.policy_name
        == sample_scan_result.pipeline
        .policy.policy_name
    )

    assert (
        report.decision.release_allowed
        == sample_scan_result.pipeline
        .release_gate.release_allowed
    )


def test_build_scan_report_maps_finding_fields(
    sample_scan_result,
) -> None:
    """Preserve normalized finding information."""
    from secureforge.reporting import (
        ReleaseMetadata,
        ScanMetadata,
    )

    release = ReleaseMetadata(
        release_id="release-002",
        application="securecommerce",
        version="1.0.0",
        commit_sha="def456",
        environment="lab",
        timestamp=(
            "2026-09-27T10:01:00+00:00"
        ),
    )

    scan = ScanMetadata(
        scan_id="scan-002",
        profile="standard",
        status="completed",
        tools=[],
        started_at=(
            "2026-09-27T10:00:00+00:00"
        ),
        completed_at=(
            "2026-09-27T10:01:00+00:00"
        ),
        duration_seconds=60.0,
    )

    report = build_scan_report(
        sample_scan_result,
        release=release,
        scan=scan,
    )

    source = (
        sample_scan_result.findings[0]
    )
    finding = report.findings[0]

    assert (
        finding.finding_id
        == source.finding_id
    )

    assert (
        finding.title
        == source.title
    )

    assert (
        finding.severity
        == source.severity.value
    )

    assert (
        finding.confidence
        == source.confidence.value
    )

    assert (
        finding.cwe
        == source.cwe
    )

    assert (
        finding.security_requirement
        == source.security_requirement
    )


def test_build_scan_report_includes_remediation_summary(
    sample_scan_result,
) -> None:
    """Calculate remediation counts from current finding state."""
    from secureforge.reporting import (
        ReleaseMetadata,
        ScanMetadata,
    )

    release = ReleaseMetadata(
        release_id="release-003",
        application="securecommerce",
        version="1.0.0",
        commit_sha="ghi789",
        environment="lab",
        timestamp=(
            "2026-09-27T10:01:00+00:00"
        ),
    )

    scan = ScanMetadata(
        scan_id="scan-003",
        profile="standard",
        status="completed",
        tools=[],
        started_at=(
            "2026-09-27T10:00:00+00:00"
        ),
        completed_at=(
            "2026-09-27T10:01:00+00:00"
        ),
        duration_seconds=60.0,
    )

    report = build_scan_report(
        sample_scan_result,
        release=release,
        scan=scan,
    )

    assert (
        report.remediation.total
        == len(
            sample_scan_result.findings
        )
    )

    assert (
        report.remediation.open
        >= 0
    )

    assert (
        report.remediation.remediated
        >= 0
    )

    assert (
        report.remediation.verified
        >= 0
    )


def test_build_scan_report_without_regression(
    sample_scan_result,
) -> None:
    """Represent scans without regression execution."""
    from secureforge.reporting import (
        ReleaseMetadata,
        ScanMetadata,
    )

    release = ReleaseMetadata(
        release_id="release-004",
        application="securecommerce",
        version="1.0.0",
        commit_sha="jkl012",
        environment="lab",
        timestamp=(
            "2026-09-27T10:01:00+00:00"
        ),
    )

    scan = ScanMetadata(
        scan_id="scan-004",
        profile="quick",
        status="completed",
        tools=["sast"],
        started_at=(
            "2026-09-27T10:00:00+00:00"
        ),
        completed_at=(
            "2026-09-27T10:01:00+00:00"
        ),
        duration_seconds=60.0,
    )

    report = build_scan_report(
        sample_scan_result,
        release=release,
        scan=scan,
    )

    assert (
        report.regression.status
        == "not_run"
    )

    assert (
        report.regression_gate
        is None
    )
```
