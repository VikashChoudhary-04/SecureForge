"""Tests for scan-result reporting adapters."""

from secureforge.core.scan.orchestrator import (
SecurityScanResult,
)
from secureforge.regression import (
RegressionGateDecision,
)
from secureforge.reporting import (
ReleaseMetadata,
ScanMetadata,
)
from secureforge.reporting.scan import (
build_scan_report,
)

def test_build_scan_report_from_scan_result(
sample_scan_execution,
sample_pipeline_result,
) -> None:
"""Convert a complete scan result into a security report."""
scan_result = SecurityScanResult(
execution=sample_scan_execution,
findings=sample_pipeline_result.findings,
pipeline=sample_pipeline_result,
)

```
release = ReleaseMetadata(
    release_id="release-001",
    application="SecureCommerce",
    version="0.1.0",
    commit_sha="abc123",
    environment="lab",
    timestamp="2026-09-27T10:00:00+00:00",
)

scan = ScanMetadata(
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

report = build_scan_report(
    scan_result,
    release=release,
    scan=scan,
    generated_at="2026-09-27T10:02:00+00:00",
)

assert report.release == release
assert report.scan == scan
assert report.findings == [
    report.findings[index]
    for index in range(
        len(report.findings)
    )
]
assert report.risk.score == (
    sample_pipeline_result.risk.score
)
assert report.policy.policy_name == (
    sample_pipeline_result.policy.policy_name
)
assert report.decision.status == (
    sample_pipeline_result.release_gate.status.value
)
assert report.decision.release_allowed == (
    sample_pipeline_result.release_gate.release_allowed
)
assert report.generated_at == (
    "2026-09-27T10:02:00+00:00"
)
```

def test_build_scan_report_includes_regression_data(
sample_scan_execution,
sample_pipeline_result,
) -> None:
"""Include regression and regression-gate data."""
regression_gate = RegressionGateDecision(
allowed=False,
status="failed",
reason="Regression test failed.",
failed_tests=("BOLA-001",),
errored_tests=(),
skipped_tests=(),
)

```
pipeline = sample_pipeline_result.model_copy(
    update={
        "regression_gate": regression_gate,
    }
)

scan_result = SecurityScanResult(
    execution=sample_scan_execution,
    findings=pipeline.findings,
    pipeline=pipeline,
)

release = ReleaseMetadata(
    release_id="release-002",
    application="SecureCommerce",
    version="0.1.0",
    commit_sha="def456",
    environment="lab",
    timestamp="2026-09-27T11:00:00+00:00",
)

scan = ScanMetadata(
    scan_id="scan-002",
    profile="full",
    status="completed",
    tools=[],
    started_at="2026-09-27T11:00:00+00:00",
    completed_at="2026-09-27T11:01:00+00:00",
    duration_seconds=60.0,
)

report = build_scan_report(
    scan_result,
    release=release,
    scan=scan,
)

assert report.regression_gate is not None
assert report.regression_gate.allowed is False
assert report.regression_gate.blocked is True
assert report.regression_gate.failed_tests == [
    "BOLA-001"
]
```

def test_build_scan_report_handles_no_regression(
sample_scan_execution,
sample_pipeline_result,
) -> None:
"""Represent a scan without regression testing."""
pipeline = sample_pipeline_result.model_copy(
update={
"regression": None,
"regression_gate": None,
}
)

```
scan_result = SecurityScanResult(
    execution=sample_scan_execution,
    findings=pipeline.findings,
    pipeline=pipeline,
)

release = ReleaseMetadata(
    release_id="release-003",
    application="SecureCommerce",
    version="0.1.0",
    commit_sha="ghi789",
    environment="lab",
    timestamp="2026-09-27T12:00:00+00:00",
)

scan = ScanMetadata(
    scan_id="scan-003",
    profile="quick",
    status="completed",
    tools=[
        "sast",
        "sca",
        "secrets",
    ],
    started_at="2026-09-27T12:00:00+00:00",
    completed_at="2026-09-27T12:00:20+00:00",
    duration_seconds=20.0,
)

report = build_scan_report(
    scan_result,
    release=release,
    scan=scan,
)

assert report.regression.suite_id == "not-run"
assert report.regression.status == "skipped"
assert report.regression_gate is None
```
