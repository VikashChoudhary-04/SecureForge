"""Tests for the SecureForge report command service."""

from pathlib import Path
from unittest.mock import Mock

from secureforge.cli.report import (
ReportCommandConfiguration,
ReportCommandService,
)
from secureforge.reporting import (
ReportPaths,
)

def build_configuration(
output_directory: Path,
) -> ReportCommandConfiguration:
"""Build report command configuration for tests."""
return ReportCommandConfiguration(
release_id="release-001",
application="SecureCommerce",
version="0.1.0",
commit_sha="abc123",
environment="lab",
scan_id="scan-001",
profile="standard",
scan_status="completed",
started_at="2026-09-27T10:00:00+00:00",
completed_at="2026-09-27T10:01:00+00:00",
duration_seconds=60.0,
output_directory=output_directory,
)

def test_report_command_builds_report() -> None:
"""Build a report from a completed scan result."""
reporting_service = Mock()

```
expected_report = object()

reporting_service.build_from_scan_result.return_value = (
    expected_report
)

service = ReportCommandService(
    reporting_service=reporting_service
)

result = object()

configuration = build_configuration(
    Path("reports")
)

report = service.build_report(
    result=result,
    configuration=configuration,
)

assert report is expected_report

reporting_service.build_from_scan_result.assert_called_once()

call = (
    reporting_service
    .build_from_scan_result
    .call_args
)

assert call.kwargs["result"] is result

release = call.kwargs["release"]
scan = call.kwargs["scan"]

assert release.release_id == "release-001"
assert release.application == "SecureCommerce"
assert release.version == "0.1.0"
assert release.commit_sha == "abc123"
assert release.environment == "lab"

assert scan.scan_id == "scan-001"
assert scan.profile == "standard"
assert scan.status == "completed"
assert scan.duration_seconds == 60.0
```

def test_report_command_generates_json_and_html(
tmp_path: Path,
) -> None:
"""Generate both JSON and HTML report files."""
reporting_service = Mock()

```
expected_paths = ReportPaths(
    json_path=(
        tmp_path
        / "security-report.json"
    ),
    html_path=(
        tmp_path
        / "security-report.html"
    ),
)

reporting_service.generate.return_value = (
    expected_paths
)

service = ReportCommandService(
    reporting_service=reporting_service
)

result = object()

configuration = build_configuration(
    tmp_path
)

paths = service.generate(
    result=result,
    configuration=configuration,
)

assert paths == expected_paths

reporting_service.generate.assert_called_once()

call = (
    reporting_service
    .generate
    .call_args
)

assert call.args[1] == expected_paths
```

def test_report_command_uses_reports_directory_by_default() -> None:
"""Use the reports directory when no output directory is supplied."""
configuration = ReportCommandConfiguration(
release_id="release-002",
application="SecureCommerce",
version="0.1.0",
commit_sha="def456",
environment="lab",
scan_id="scan-002",
profile="quick",
scan_status="completed",
started_at="2026-09-27T11:00:00+00:00",
completed_at="2026-09-27T11:00:30+00:00",
duration_seconds=30.0,
)

```
assert configuration.output_directory == Path(
    "reports"
)
```

def test_report_command_output_paths_are_standardized(
tmp_path: Path,
) -> None:
"""Use stable report filenames inside the configured directory."""
reporting_service = Mock()

```
reporting_service.build_from_scan_result.return_value = (
    object()
)

reporting_service.generate.return_value = (
    ReportPaths(
        json_path=(
            tmp_path
            / "security-report.json"
        ),
        html_path=(
            tmp_path
            / "security-report.html"
        ),
    )
)

service = ReportCommandService(
    reporting_service=reporting_service
)

service.generate(
    result=object(),
    configuration=build_configuration(
        tmp_path
    ),
)

paths = (
    reporting_service
    .generate
    .call_args.args[1]
)

assert paths.json_path.name == (
    "security-report.json"
)
assert paths.html_path.name == (
    "security-report.html"
)
assert paths.json_path.parent == tmp_path
assert paths.html_path.parent == tmp_path
```
