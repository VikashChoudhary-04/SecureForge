```python id="n4v7qs"
"""Tests for SecureForge report command services."""

from pathlib import Path

from secureforge.cli.report import (
    ReportCommandConfiguration,
    ReportCommandService,
)
from secureforge.reporting import (
    SecurityReportLoader,
    SecurityReportService,
)


def test_report_command_service_builds_report(
    sample_scan_result,
) -> None:
    """Build a security report from a completed scan."""
    service = ReportCommandService()

    configuration = ReportCommandConfiguration(
        release_id="release-001",
        application="securecommerce",
        version="1.0.0",
        commit_sha="abc123",
        environment="lab",
        scan_id="scan-001",
        profile="standard",
        scan_status="completed",
        started_at="2026-09-27T10:00:00+00:00",
        completed_at="2026-09-27T10:01:00+00:00",
        duration_seconds=60.0,
    )

    report = service.build_report(
        result=sample_scan_result,
        configuration=configuration,
    )

    assert report.release.release_id == "release-001"
    assert report.release.application == "securecommerce"
    assert report.scan.scan_id == "scan-001"


def test_report_command_service_generates_reports(
    sample_scan_result,
    tmp_path: Path,
) -> None:
    """Generate JSON and HTML reports from a scan result."""
    service = ReportCommandService()

    configuration = ReportCommandConfiguration(
        release_id="release-002",
        application="securecommerce",
        version="1.0.0",
        commit_sha="def456",
        environment="lab",
        scan_id="scan-002",
        profile="standard",
        scan_status="completed",
        started_at="2026-09-27T10:00:00+00:00",
        completed_at="2026-09-27T10:01:00+00:00",
        duration_seconds=60.0,
        output_directory=tmp_path,
    )

    paths = service.generate(
        result=sample_scan_result,
        configuration=configuration,
    )

    assert paths.json_path.exists()
    assert paths.html_path.exists()

    assert (
        paths.json_path.read_text(
            encoding="utf-8"
        )
    )

    assert (
        paths.html_path.read_text(
            encoding="utf-8"
        )
    )


def test_report_command_service_loads_report(
    sample_security_report,
    tmp_path: Path,
) -> None:
    """Load a persisted security report."""
    path = (
        tmp_path
        / "security-report.json"
    )

    path.write_text(
        sample_security_report.model_dump_json(
            indent=2
        ),
        encoding="utf-8",
    )

    service = ReportCommandService(
        report_loader=SecurityReportLoader()
    )

    report = service.load(path)

    assert report == sample_security_report


def test_report_command_service_regenerates_html(
    sample_security_report,
    tmp_path: Path,
) -> None:
    """Regenerate HTML from an existing JSON report."""
    json_path = (
        tmp_path
        / "security-report.json"
    )

    html_path = (
        tmp_path
        / "regenerated.html"
    )

    json_path.write_text(
        sample_security_report.model_dump_json(
            indent=2
        ),
        encoding="utf-8",
    )

    service = ReportCommandService()

    result_path = service.regenerate_html(
        json_path=json_path,
        html_path=html_path,
    )

    assert result_path == html_path
    assert html_path.exists()

    html = html_path.read_text(
        encoding="utf-8"
    )

    assert "<html" in html
    assert "SecureForge" in html
```
