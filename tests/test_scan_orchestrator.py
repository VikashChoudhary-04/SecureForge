```python id="p4x8wm"
"""Tests for SecureForge scan orchestration."""

from datetime import datetime

from secureforge.core.scan.orchestrator import (
    ScanOrchestrator,
)


class FakeScanRunner:
    """Minimal scan runner for orchestration tests."""

    def __init__(
        self,
        execution,
    ) -> None:
        self.execution = execution
        self.calls: list[dict[str, object]] = []

    def run(
        self,
        *,
        scan_id: str,
        profile: str,
        target: str,
        source_path: str | None = None,
    ):
        self.calls.append(
            {
                "scan_id": scan_id,
                "profile": profile,
                "target": target,
                "source_path": source_path,
            }
        )

        return self.execution


class FakePipeline:
    """Minimal security pipeline for orchestration tests."""

    def __init__(
        self,
        result,
    ) -> None:
        self.result = result
        self.calls: list[dict[str, object]] = []

    def evaluate(
        self,
        findings,
        *,
        tool_errors,
        regression=None,
        regression_gate=None,
    ):
        self.calls.append(
            {
                "findings": findings,
                "tool_errors": tool_errors,
                "regression": regression,
                "regression_gate": regression_gate,
            }
        )

        return self.result


def test_scan_orchestrator_runs_runner_and_pipeline(
    sample_scan_execution,
    sample_pipeline_result,
) -> None:
    """Coordinate scan execution and security evaluation."""
    runner = FakeScanRunner(
        sample_scan_execution
    )

    pipeline = FakePipeline(
        sample_pipeline_result
    )

    orchestrator = ScanOrchestrator(
        runner=runner,
        pipeline=pipeline,
    )

    result = orchestrator.run(
        scan_id="scan-001",
        profile="standard",
        target="http://127.0.0.1:5000",
    )

    assert result.execution is sample_scan_execution
    assert result.pipeline is sample_pipeline_result

    assert runner.calls == [
        {
            "scan_id": "scan-001",
            "profile": "standard",
            "target": "http://127.0.0.1:5000",
            "source_path": None,
        }
    ]

    assert len(
        pipeline.calls
    ) == 1

    assert (
        pipeline.calls[0]["findings"]
        == sample_scan_execution.findings
    )

    assert (
        pipeline.calls[0]["tool_errors"]
        == sample_scan_execution.errors
    )


def test_scan_orchestrator_passes_regression_inputs(
    sample_scan_execution,
    sample_pipeline_result,
) -> None:
    """Forward regression results into the security pipeline."""
    runner = FakeScanRunner(
        sample_scan_execution
    )

    pipeline = FakePipeline(
        sample_pipeline_result
    )

    orchestrator = ScanOrchestrator(
        runner=runner,
        pipeline=pipeline,
    )

    result = orchestrator.run(
        scan_id="scan-002",
        profile="full",
        target="http://127.0.0.1:5000",
        regression_result=None,
        regression_gate=None,
    )

    assert result.pipeline is sample_pipeline_result

    assert (
        pipeline.calls[0]["regression"]
        is None
    )

    assert (
        pipeline.calls[0]["regression_gate"]
        is None
    )


def test_scan_orchestrator_sets_execution_timestamps(
    sample_scan_execution,
    sample_pipeline_result,
) -> None:
    """Record execution start and completion timestamps."""
    sample_scan_execution.started_at = None
    sample_scan_execution.completed_at = None

    runner = FakeScanRunner(
        sample_scan_execution
    )

    pipeline = FakePipeline(
        sample_pipeline_result
    )

    orchestrator = ScanOrchestrator(
        runner=runner,
        pipeline=pipeline,
    )

    result = orchestrator.run(
        scan_id="scan-003",
        profile="quick",
        target="http://127.0.0.1:5000",
    )

    assert result.execution.started_at is not None
    assert result.execution.completed_at is not None

    started = datetime.fromisoformat(
        result.execution.started_at
    )

    completed = datetime.fromisoformat(
        result.execution.completed_at
    )

    assert (
        completed
        >= started
    )


def test_security_scan_result_properties(
    sample_scan_result,
) -> None:
    """Expose release-gate state through scan-result properties."""
    assert (
        sample_scan_result.release_allowed
        == sample_scan_result.pipeline.release_allowed
    )

    assert (
        sample_scan_result.release_blocked
        == sample_scan_result.pipeline.release_blocked
    )

    assert (
        sample_scan_result.release_status
        == sample_scan_result.pipeline
        .release_gate.status.value
    )


def test_security_scan_result_to_dict(
    sample_scan_result,
) -> None:
    """Serialize the complete scan result."""
    payload = (
        sample_scan_result.to_dict()
    )

    assert set(
        payload
    ) == {
        "scan",
        "findings",
        "pipeline",
    }

    assert (
        payload["scan"]["scan_id"]
        == sample_scan_result.execution.scan_id
    )

    assert isinstance(
        payload["findings"],
        list,
    )

    assert isinstance(
        payload["pipeline"],
        dict,
    )
```
