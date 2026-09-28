```python id="8k4n1q"
"""Scan orchestration for SecureForge."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from secureforge.validation.models import ValidationRequest

from .models import ScanExecution, SecurityScanResult
from .runner import ScanRunner
from .security_pipeline import SecurityPipeline


class ScanOrchestrator:
    """Coordinate tool execution and security verification."""

    def __init__(
        self,
        *,
        runner: ScanRunner,
        pipeline: SecurityPipeline,
    ) -> None:
        self.runner = runner
        self.pipeline = pipeline

    def run(
        self,
        *,
        scan_id: str,
        profile: str,
        target: str | None = None,
        source_path: str | Path | None = None,
        application: str = "unknown",
        version: str = "unknown",
        commit_sha: str | None = None,
        environment: str = "lab",
        validation_requests: list[ValidationRequest] | None = None,
        run_regression: bool = False,
    ) -> SecurityScanResult:
        """Execute a scan and process its findings."""
        started_at = datetime.now(timezone.utc)

        execution = self.runner.run(
            scan_id=scan_id,
            profile=profile,
            target=target,
            source_path=source_path,
            application=application,
            version=version,
            commit_sha=commit_sha,
            environment=environment,
        )

        pipeline_result = self.pipeline.run(
            execution.findings,
            validation_requests=validation_requests,
            run_regression=run_regression,
        )

        completed_at = datetime.now(timezone.utc)

        scan_execution = ScanExecution(
            scan_id=scan_id,
            profile=profile,
            application=application,
            version=version,
            commit_sha=commit_sha,
            environment=environment,
            started_at=started_at.isoformat(),
            completed_at=completed_at.isoformat(),
            status=execution.status,
            tools=execution.tools,
            tool_errors=execution.tool_errors,
        )

        return SecurityScanResult(
            execution=scan_execution,
            findings=pipeline_result.findings,
            pipeline=pipeline_result,
        )
```
