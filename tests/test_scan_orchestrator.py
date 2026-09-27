"""Tests for SecureForge scan orchestration."""

from unittest.mock import Mock

from secureforge.core.scan.models import (
ScanExecution,
ScanStatus,
)
from secureforge.core.scan.orchestrator import (
ScanOrchestrator,
)
from secureforge.regression import (
RegressionGateDecision,
RegressionStatus,
RegressionSuiteResult,
)

def build_scan_execution(
*,
findings=None,
errors=None,
status=ScanStatus.COMPLETED,
) -> ScanExecution:
"""Build a scan execution for orchestration tests."""
return ScanExecution(
scan_id="scan-001",
profile="standard",
target="http://127.0.0.1:5000",
status=status,
findings=(
findings
if findings is not None
else []
),
errors=(
errors
if errors is not None
else []
),
warnings=[],
started_at=None,
completed_at=None,
)

def build_regression_result(
*,
status: RegressionStatus,
) -> RegressionSuiteResult:
"""Build a regression result for orchestration tests."""
return RegressionSuiteResult(
suite_id="securecommerce-regression",
name="SecureCommerce Regression",
status=status,
results=[],
started_at="2026-09-27T10:00:00+00:00",
completed_at="2026-09-27T10:00:01+00:00",
duration_seconds=1.0,
)

def test_orchestrator_runs_scan_and_pipeline(
sample_findings,
) -> None:
"""Run scan execution and pass its findings to the pipeline."""
execution = build_scan_execution(
findings=sample_findings
)

```
runner = Mock()
runner.run.return_value = execution

orchestrator = ScanOrchestrator(
    runner=runner,
)

result = orchestrator.run(
    scan_id="scan-001",
    profile="standard",
    target="http://127.0.0.1:5000",
)

runner.run.assert_called_once_with(
    scan_id="scan-001",
    profile="standard",
    target="http://127.0.0.1:5000",
    source_path=None,
)

assert result.execution is execution
assert result.findings
assert result.pipeline is not None
assert result.pipeline.release_gate is not None
```

def test_orchestrator_passes_tool_errors_to_pipeline(
sample_findings,
) -> None:
"""Forward scan execution errors to the security pipeline."""
execution = build_scan_execution(
findings=sample_findings,
errors=["nmap failed"],
)

```
runner = Mock()
runner.run.return_value = execution

orchestrator = ScanOrchestrator(
    runner=runner,
)

result = orchestrator.run(
    scan_id="scan-002",
    profile="standard",
    target="http://127.0.0.1:5000",
)

assert result.execution.errors == [
    "nmap failed"
]
assert "nmap failed" in (
    result.pipeline.policy.tool_errors
)
```

def test_orchestrator_passes_regression_results_to_pipeline(
sample_findings,
) -> None:
"""Forward regression results to the security pipeline."""
execution = build_scan_execution(
findings=sample_findings
)

```
regression = build_regression_result(
    status=RegressionStatus.PASSED
)

runner = Mock()
runner.run.return_value = execution

orchestrator = ScanOrchestrator(
    runner=runner,
)

result = orchestrator.run(
    scan_id="scan-003",
    profile="standard",
    target="http://127.0.0.1:5000",
    regression_result=regression,
)

assert result.pipeline.regression is regression
assert result.pipeline.regression_gate is not None
```

def test_orchestrator_accepts_explicit_regression_gate(
sample_findings,
) -> None:
"""Forward an explicit regression-gate decision."""
execution = build_scan_execution(
findings=sample_findings
)

```
regression_gate = RegressionGateDecision(
    allowed=False,
    status="failed",
    reason="Regression test failed.",
    failed_tests=("BOLA-001",),
    errored_tests=(),
    skipped_tests=(),
)

runner = Mock()
runner.run.return_value = execution

orchestrator = ScanOrchestrator(
    runner=runner,
)

result = orchestrator.run(
    scan_id="scan-004",
    profile="standard",
    target="http://127.0.0.1:5000",
    regression_gate=regression_gate,
)

assert result.pipeline.regression_gate is regression_gate
assert result.release_allowed is False
assert result.release_blocked is True
```

def test_security_scan_result_exposes_release_decision(
sample_findings,
) -> None:
"""Expose the final release decision through the scan result."""
execution = build_scan_execution(
findings=sample_findings
)

```
runner = Mock()
runner.run.return_value = execution

orchestrator = ScanOrchestrator(
    runner=runner,
)

result = orchestrator.run(
    scan_id="scan-005",
    profile="standard",
    target="http://127.0.0.1:5000",
)

assert isinstance(
    result.release_allowed,
    bool,
)
assert isinstance(
    result.release_blocked,
    bool,
)
assert result.release_blocked == (
    not result.release_allowed
)
assert result.release_status == (
    result.pipeline.release_gate.status.value
)
```

def test_security_scan_result_to_dict(
sample_findings,
) -> None:
"""Serialize the complete scan result."""
execution = build_scan_execution(
findings=sample_findings
)

```
runner = Mock()
runner.run.return_value = execution

orchestrator = ScanOrchestrator(
    runner=runner,
)

result = orchestrator.run(
    scan_id="scan-006",
    profile="standard",
    target="http://127.0.0.1:5000",
)

serialized = result.to_dict()

assert "scan" in serialized
assert "findings" in serialized
assert "pipeline" in serialized
assert "release_allowed" in (
    serialized["pipeline"]
)
```
