"""Tests for SecureForge scan orchestration models."""

from secureforge.core.config import ScanProfile
from secureforge.core.findings import (
Finding,
Severity,
)
from secureforge.core.scan import (
ScanRun,
ScanStatus,
ScanSummary,
ToolExecutionResult,
ToolExecutionStatus,
)

def build_scan() -> ScanRun:
"""Create a representative SecureForge scan."""
return ScanRun(
scan_id="SCAN-001",
application="SecureCommerce",
version="1.0.0",
profile=ScanProfile.STANDARD,
environment="lab",
commit_sha="abc123",
)

def build_finding(
finding_id: str,
severity: Severity,
) -> Finding:
"""Create a representative finding."""
return Finding(
finding_id=finding_id,
title=f"Test {severity.value} finding",
source="test",
application="SecureCommerce",
asset="securecommerce-api",
severity=severity,
description="Controlled test finding.",
impact="Controlled test impact.",
remediation="Controlled test remediation.",
)

def test_scan_is_created_by_default() -> None:
"""Verify a new scan starts in CREATED state."""
scan = build_scan()

```
assert scan.status == ScanStatus.CREATED
assert scan.completed_at is None
assert scan.started_at is not None
```

def test_scan_start_changes_status() -> None:
"""Verify starting a scan changes its lifecycle state."""
scan = build_scan()

```
scan.start()

assert scan.status == ScanStatus.RUNNING
```

def test_scan_complete_changes_status() -> None:
"""Verify completing a scan records completion time."""
scan = build_scan()

```
scan.start()
scan.complete()

assert scan.status == ScanStatus.COMPLETED
assert scan.completed_at is not None
assert scan.is_finished is True
```

def test_scan_failure_records_error() -> None:
"""Verify failed scans retain their failure reason."""
scan = build_scan()

```
scan.fail("Scanner execution failed.")

assert scan.status == ScanStatus.FAILED
assert scan.completed_at is not None
assert scan.errors == [
    "Scanner execution failed."
]
assert scan.has_errors is True
assert scan.is_finished is True
```

def test_duplicate_scan_errors_are_not_added() -> None:
"""Verify duplicate scan errors are ignored."""
scan = build_scan()

```
scan.add_error("Tool failed.")
scan.add_error("Tool failed.")

assert scan.errors == [
    "Tool failed."
]
```

def test_scan_warning_is_recorded() -> None:
"""Verify scan warnings are retained."""
scan = build_scan()

```
scan.add_warning(
    "Optional scanner was unavailable."
)

assert scan.warnings == [
    "Optional scanner was unavailable."
]
```

def test_duplicate_scan_warnings_are_not_added() -> None:
"""Verify duplicate warnings are ignored."""
scan = build_scan()

```
scan.add_warning("Warning.")
scan.add_warning("Warning.")

assert scan.warnings == [
    "Warning."
]
```

def test_successful_tool_result_is_tracked() -> None:
"""Verify successful tool executions update scan statistics."""
scan = build_scan()

```
result = ToolExecutionResult(
    tool_name="Semgrep",
    integration="sast",
    status=ToolExecutionStatus.SUCCESS,
    command=[
        "semgrep",
        "--config",
        "auto",
    ],
    exit_code=0,
    stdout="No findings.",
    duration_seconds=2.5,
)

scan.add_tool_result(result)

assert scan.tool_results == [result]
assert scan.summary.tool_count == 1
assert scan.summary.successful_tools == 1
assert scan.summary.failed_tools == 0
assert scan.summary.skipped_tools == 0
assert scan.tool_error_count == 0
```

def test_failed_tool_result_is_tracked() -> None:
"""Verify failed tool executions update scan statistics."""
scan = build_scan()

```
result = ToolExecutionResult(
    tool_name="Nmap",
    integration="nmap",
    status=ToolExecutionStatus.FAILED,
    command=[
        "nmap",
        "127.0.0.1",
    ],
    exit_code=1,
    stderr="Execution failed.",
    duration_seconds=1.2,
    error="Nmap execution failed.",
)

scan.add_tool_result(result)

assert scan.summary.tool_count == 1
assert scan.summary.successful_tools == 0
assert scan.summary.failed_tools == 1
assert scan.tool_error_count == 1
```

def test_timeout_counts_as_tool_failure() -> None:
"""Verify timed-out integrations count as failures."""
scan = build_scan()

```
result = ToolExecutionResult(
    tool_name="DAST",
    integration="dast",
    status=ToolExecutionStatus.TIMEOUT,
    duration_seconds=300.0,
    error="Execution timed out.",
)

scan.add_tool_result(result)

assert scan.summary.failed_tools == 1
assert scan.tool_error_count == 1
```

def test_skipped_tool_is_tracked() -> None:
"""Verify skipped integrations are counted separately."""
scan = build_scan()

```
result = ToolExecutionResult(
    tool_name="Nessus",
    integration="nessus",
    status=ToolExecutionStatus.SKIPPED,
)

scan.add_tool_result(result)

assert scan.summary.tool_count == 1
assert scan.summary.skipped_tools == 1
assert scan.summary.failed_tools == 0
```

def test_tool_result_success_property() -> None:
"""Verify successful execution property."""
result = ToolExecutionResult(
tool_name="SCA",
integration="sca",
status=ToolExecutionStatus.SUCCESS,
)

```
assert result.succeeded is True
assert result.failed is False
```

def test_tool_result_failure_property() -> None:
"""Verify failed execution property."""
result = ToolExecutionResult(
tool_name="SCA",
integration="sca",
status=ToolExecutionStatus.FAILED,
)

```
assert result.succeeded is False
assert result.failed is True
```

def test_timeout_result_is_failed() -> None:
"""Verify timeout is treated as a failed execution."""
result = ToolExecutionResult(
tool_name="DAST",
integration="dast",
status=ToolExecutionStatus.TIMEOUT,
)

```
assert result.succeeded is False
assert result.failed is True
```

def test_findings_update_scan_summary() -> None:
"""Verify finding severity counters are calculated."""
scan = build_scan()

```
findings = [
    build_finding(
        "SF-001",
        Severity.CRITICAL,
    ),
    build_finding(
        "SF-002",
        Severity.HIGH,
    ),
    build_finding(
        "SF-003",
        Severity.MEDIUM,
    ),
    build_finding(
        "SF-004",
        Severity.LOW,
    ),
    build_finding(
        "SF-005",
        Severity.INFO,
    ),
]

scan.add_findings(findings)

assert scan.has_findings is True
assert scan.summary.finding_count == 5
assert scan.summary.critical_findings == 1
assert scan.summary.high_findings == 1
assert scan.summary.medium_findings == 1
assert scan.summary.low_findings == 1
assert scan.summary.info_findings == 1
```

def test_adding_findings_updates_existing_summary() -> None:
"""Verify summary counters reflect the complete finding collection."""
scan = build_scan()

```
scan.add_findings(
    [
        build_finding(
            "SF-001",
            Severity.HIGH,
        )
    ]
)

scan.add_findings(
    [
        build_finding(
            "SF-002",
            Severity.MEDIUM,
        )
    ]
)

assert scan.summary.finding_count == 2
assert scan.summary.high_findings == 1
assert scan.summary.medium_findings == 1
```

def test_regression_failure_is_tracked() -> None:
"""Verify failed regression identifiers are retained."""
scan = build_scan()

```
scan.add_regression_failure(
    "BOLA-001"
)

assert scan.regression_failures == [
    "BOLA-001"
]
assert scan.summary.regression_failure_count == 1
```

def test_duplicate_regression_failure_is_not_added() -> None:
"""Verify duplicate regression failures are ignored."""
scan = build_scan()

```
scan.add_regression_failure(
    "BOLA-001"
)

scan.add_regression_failure(
    "BOLA-001"
)

assert scan.regression_failures == [
    "BOLA-001"
]
assert scan.summary.regression_failure_count == 1
```

def test_scan_summary_defaults_are_zero() -> None:
"""Verify a new scan summary starts empty."""
summary = ScanSummary()

```
assert summary.tool_count == 0
assert summary.successful_tools == 0
assert summary.failed_tools == 0
assert summary.skipped_tools == 0
assert summary.finding_count == 0
assert summary.critical_findings == 0
assert summary.high_findings == 0
assert summary.medium_findings == 0
assert summary.low_findings == 0
assert summary.info_findings == 0
assert summary.correlated_group_count == 0
assert summary.regression_failure_count == 0
```

def test_scan_profile_is_preserved() -> None:
"""Verify the selected scan profile remains available."""
scan = build_scan()

```
assert scan.profile == ScanProfile.STANDARD
```

def test_scan_identity_is_preserved() -> None:
"""Verify application and release identity are preserved."""
scan = build_scan()

```
assert scan.scan_id == "SCAN-001"
assert scan.application == "SecureCommerce"
assert scan.version == "1.0.0"
assert scan.environment == "lab"
assert scan.commit_sha == "abc123"
```

def test_empty_scan_has_no_findings_or_errors() -> None:
"""Verify a new scan has clean collections."""
scan = build_scan()

```
assert scan.has_findings is False
assert scan.has_errors is False
assert scan.tool_error_count == 0
assert scan.regression_failures == []
```

def test_scan_can_store_metadata() -> None:
"""Verify arbitrary operational metadata can be preserved."""
scan = build_scan()

```
scan.metadata = {
    "trigger": "pull_request",
    "branch": "main",
}

assert scan.metadata["trigger"] == "pull_request"
assert scan.metadata["branch"] == "main"
```

def test_multiple_tool_results_update_all_statistics() -> None:
"""Verify aggregate tool statistics remain accurate."""
scan = build_scan()

```
scan.add_tool_result(
    ToolExecutionResult(
        tool_name="SAST",
        integration="sast",
        status=ToolExecutionStatus.SUCCESS,
    )
)

scan.add_tool_result(
    ToolExecutionResult(
        tool_name="SCA",
        integration="sca",
        status=ToolExecutionStatus.SUCCESS,
    )
)

scan.add_tool_result(
    ToolExecutionResult(
        tool_name="DAST",
        integration="dast",
        status=ToolExecutionStatus.FAILED,
    )
)

scan.add_tool_result(
    ToolExecutionResult(
        tool_name="Nessus",
        integration="nessus",
        status=ToolExecutionStatus.SKIPPED,
    )
)

assert scan.summary.tool_count == 4
assert scan.summary.successful_tools == 2
assert scan.summary.failed_tools == 1
assert scan.summary.skipped_tools == 1
assert scan.tool_error_count == 1
```
