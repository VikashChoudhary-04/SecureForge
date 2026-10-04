"""Regression tests for scan-orchestrator tool-error propagation."""

from __future__ import annotations

from datetime import datetime, timezone

from secureforge.core.release_gate import ReleaseDecision
from secureforge.core.scan.models import (
    ScanRun,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from secureforge.core.scan.orchestrator import ScanOrchestrator


class ToolErrorScanRunner:
    """Return a scan run containing a failed security tool."""

    def run(
        self,
        *,
        scan_id: str,
        profile: str,
        target: str,
        source_path: str | None = None,
    ) -> ScanRun:
        """Return a completed scan containing a scanner execution error."""
        timestamp = datetime.now(timezone.utc)

        scan = ScanRun(
            scan_id=scan_id,
            profile=profile,
            application="securecommerce",
            version="1.0.0",
            environment="lab",
        )

        scan.start()

        scan.add_tool_result(
            ToolExecutionResult(
                tool_name="dast",
                integration="dast",
                status=ToolExecutionStatus.FAILED,
                command=["dast", "--scan"],
                exit_code=1,
                error="DAST scanner failed to execute.",
                started_at=timestamp,
                completed_at=timestamp,
            )
        )

        scan.complete()

        return scan


def test_scan_orchestrator_propagates_real_tool_errors_to_pipeline() -> None:
    """Real scanner execution errors must reach policy and release evaluation."""
    orchestrator = ScanOrchestrator(
        runner=ToolErrorScanRunner()
    )

    result = orchestrator.run(
        scan_id="scan-tool-error-001",
        profile="standard",
        target="http://localhost:5000",
    )

    assert result.execution.tool_errors == [
        "DAST scanner failed to execute.",
    ]

    assert result.pipeline.policy is not None
    assert any(
        "DAST scanner failed to execute." in violation
        for violation in result.pipeline.policy.violations
    )

    assert result.pipeline.release_gate is not None
    assert result.pipeline.release_gate.decision == (
        ReleaseDecision.REVIEW
    )
