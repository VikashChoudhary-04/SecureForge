```python id="r6k2mv"
"""Scan orchestration for SecureForge."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from secureforge.core.findings.models import Finding
from secureforge.core.scan.models import (
    ScanExecution,
)
from secureforge.regression import (
    RegressionGateDecision,
    RegressionSuiteResult,
)

from .runner import ScanRunner
from .security_pipeline import (
    SecurityPipeline,
    SecurityPipelineResult,
)


@dataclass(frozen=True)
class SecurityScanResult:
    """Complete result of a SecureForge security scan."""

    execution: ScanExecution
    findings: list[Finding]
    pipeline: SecurityPipelineResult

    @property
    def release_allowed(self) -> bool:
        """Return whether the release is allowed."""
        return self.pipeline.release_allowed

    @property
    def release_blocked(self) -> bool:
        """Return whether the release is blocked."""
        return self.pipeline.release_blocked

    @property
    def release_status(self) -> str:
        """Return the final release-gate status."""
        return self.pipeline.release_gate.status.value

    def to_dict(self) -> dict[str, Any]:
        """Serialize the complete scan result."""
        return {
            "scan": self.execution.model_dump(),
            "findings": [
                finding.model_dump(
                    mode="json"
                )
                for finding in self.findings
            ],
            "pipeline": (
                self.pipeline.summarize(
                    self.pipeline
                )
            ),
        }


class ScanOrchestrator:
    """Coordinate scan execution and security evaluation."""

    def __init__(
        self,
        *,
        runner: ScanRunner,
        pipeline: SecurityPipeline | None = None,
    ) -> None:
        self.runner = runner
        self.pipeline = (
            pipeline
            if pipeline is not None
            else SecurityPipeline()
        )

    def run(
        self,
        *,
        scan_id: str,
        profile: str,
        target: str,
        source_path: str | None = None,
        regression_result: RegressionSuiteResult | None = None,
        regression_gate: RegressionGateDecision | None = None,
    ) -> SecurityScanResult:
        """Run a scan and evaluate its security results."""
        started_at = datetime.now(
            timezone.utc
        )

        execution = self.runner.run(
            scan_id=scan_id,
            profile=profile,
            target=target,
            source_path=source_path,
        )

        findings = list(
            execution.findings
        )

        pipeline_result = self.pipeline.evaluate(
            findings,
            tool_errors=list(
                execution.errors
            ),
            regression=regression_result,
            regression_gate=regression_gate,
        )

        completed_at = datetime.now(
            timezone.utc
        )

        execution.started_at = (
            started_at.isoformat()
        )
        execution.completed_at = (
            completed_at.isoformat()
        )

        return SecurityScanResult(
            execution=execution,
            findings=pipeline_result.findings,
            pipeline=pipeline_result,
        )
```
