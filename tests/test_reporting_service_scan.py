```python id="j8k4px"
"""Tests for generating reports from completed scan results."""

from pathlib import Path

from secureforge.reporting import (
    ReleaseMetadata,
    ReportPaths,
    ScanMetadata,
    SecurityReportService,
)


def test_build_from_scan_result(
    sample_scan_result,
) -> None:
    """Build a report directly from a completed scan result."""
    service = SecurityReportService()

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

    report = service.build_from_scan_result(
        result=sample_scan_result,
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
    assert report.policy.policy_name == (
        sample_scan_result.pipeline.policy.policy_name
    )
    assert report.decision.release_allowed == (
        sample_scan_result.pipeline
        .release_gate
        .release_allowed
    )


def test_generate_from_scan_result(
    sample_scan_result,
    tmp_path: Path,
) -> None:
    """Generate JSON and HTML reports from a scan result."""
    service = SecurityReportService()

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

    paths = ReportPaths(
        json_path=tmp_path / "security-report.json",
        html_path=tmp_path / "security-report.html",
    )

    generated = service.generate_from_scan_result(
        result=sample_scan_result,
        release=release,
        scan=scan,
        paths=paths,
    )

    assert generated == paths
    assert paths.json_path.is_file()
    assert paths.html_path.is_file()

    assert paths.json_path.read_text(
        encoding="utf-8"
    )

    assert paths.html_path.read_text(
        encoding="utf-8"
    )
```
