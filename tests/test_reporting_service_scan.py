"""Tests for scan-result integration in the reporting service."""

from pathlib import Path

from secureforge.core.scan.orchestrator import (
SecurityScanResult,
)
from secureforge.reporting import (
ReleaseMetadata,
ReportPaths,
ScanMetadata,
SecurityReportService,
)

def build_release_metadata() -> ReleaseMetadata:
"""Build release metadata for reporting tests."""
return ReleaseMetadata(
release_id="release-scan-001",
application="SecureCommerce",
version="0.1.0",
commit_sha="abc123",
environment="lab",
timestamp="2026-09-27T10:00:00+00:00",
)

def build_scan_metadata() -> ScanMetadata:
"""Build scan metadata for reporting tests."""
return ScanMetadata(
scan_id="scan-001",
profile="standard",
status="completed",
tools=[
"sast",
"sca",
"secrets",
"api",
"dast",
],
started_at="2026-09-27T10:00:00+00:00",
completed_at="2026-09-27T10:01:00+00:00",
duration_seconds=60.0,
)

def test_service_builds_report_from_scan_result(
sample_scan_execution,
sample_pipeline_result,
) -> None:
"""Build a report directly from a completed scan result."""
scan_result = SecurityScanResult(
execution=sample_scan_execution,
findings=sample_pipeline_result.findings,
pipeline=sample_pipeline_result,
)

```
service = SecurityReportService()

report = service.build_from_scan_result(
    result=scan_result,
    release=build_release_metadata(),
    scan=build_scan_metadata(),
    generated_at="2026-09-27T10:02:00+00:00",
)

assert report.release.release_id == (
    "release-scan-001"
)
assert report.scan.scan_id == "scan-001"
assert report.decision.release_allowed == (
    scan_result.release_allowed
)
assert report.decision.status == (
    scan_result.release_status
)
assert report.generated_at == (
    "2026-09-27T10:02:00+00:00"
)
```

def test_service_generates_files_from_scan_result(
sample_scan_execution,
sample_pipeline_result,
tmp_path: Path,
) -> None:
"""Generate JSON and HTML reports directly from a scan result."""
scan_result = SecurityScanResult(
execution=sample_scan_execution,
findings=sample_pipeline_result.findings,
pipeline=sample_pipeline_result,
)

```
service = SecurityReportService()

paths = ReportPaths(
    json_path=tmp_path / "security-report.json",
    html_path=tmp_path / "security-report.html",
)

result_paths = service.generate_from_scan_result(
    result=scan_result,
    release=build_release_metadata(),
    scan=build_scan_metadata(),
    paths=paths,
)

assert result_paths == paths
assert paths.json_path.exists()
assert paths.html_path.exists()

json_content = paths.json_path.read_text(
    encoding="utf-8"
)

assert '"release"' in json_content
assert '"scan"' in json_content
assert '"findings"' in json_content
assert '"risk"' in json_content
assert '"policy"' in json_content
assert '"regression"' in json_content
assert '"decision"' in json_content

html_content = paths.html_path.read_text(
    encoding="utf-8"
)

assert "SecureForge Security Report" in html_content
assert "Release Decision" in html_content
assert "Regression Testing" in html_content
```

def test_service_preserves_regression_gate_in_scan_report(
sample_scan_execution,
sample_pipeline_result,
) -> None:
"""Preserve regression-gate information in generated reports."""
scan_result = SecurityScanResult(
execution=sample_scan_execution,
findings=sample_pipeline_result.findings,
pipeline=sample_pipeline_result,
)

```
service = SecurityReportService()

report = service.build_from_scan_result(
    result=scan_result,
    release=build_release_metadata(),
    scan=build_scan_metadata(),
)

if scan_result.pipeline.regression_gate is None:
    assert report.regression_gate is None
else:
    assert report.regression_gate is not None
    assert (
        report.regression_gate.status
        == scan_result.pipeline.regression_gate.status
    )
```
