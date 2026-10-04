"""Regression tests for scan-orchestrator tool-error propagation."""

from __future__ import annotations

from secureforge.core.release_gate import ReleaseDecision
from secureforge.core.scan.models import ScanExecution, ScanStatus
from secureforge.core.scan.orchestrator import ScanOrchestrator


class ToolErrorScanRunner:
    """Return a scan execution containing a scanner execution error."""

    def run(
        self,
        *,
        scan_id: str,
        profile: str,
        target: str,
        source_path: str | None = None,
    ) -> ScanExecution:
        """Return a completed scan with a tool error."""
        return ScanExecution(
            scan_id=scan_id,
            profile=profile,
            target=target,
            status=ScanStatus.COMPLETED,
            findings=[],
            tool_errors=[
                "DAST scanner failed to execute.",
            ],
            started_at="2026-10-04T10:00:00+00:00",
            completed_at="2026-10-04T10:05:00+00:00",
        )


def test_scan_orchestrator_propagates_tool_errors_to_pipeline() -> None:
    """Scanner execution errors must reach policy and release evaluation."""
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
