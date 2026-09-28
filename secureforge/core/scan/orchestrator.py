"""Scan orchestration for SecureForge."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from secureforge.validation.models import (
    ValidationMethod,
    ValidationRequest,
)
from secureforge.validation.planner import ValidationPlanner

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
        validation_planner: ValidationPlanner | None = None,
    ) -> None:
        self.runner = runner
        self.pipeline = pipeline
        self.validation_planner = (
            validation_planner
            if validation_planner is not None
            else ValidationPlanner()
        )

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
        validate_findings: bool = False,
        validation_method: ValidationMethod = ValidationMethod.HTTP,
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

        planned_validation_requests = (
            self._plan_validation_requests(
                findings=execution.findings,
                target=target,
                method=validation_method,
            )
            if validate_findings
            else []
        )

        effective_validation_requests = (
            validation_requests
            if validation_requests is not None
            else planned_validation_requests
        )

        pipeline_result = self.pipeline.run(
            execution.findings,
            validation_requests=(
                effective_validation_requests
                if effective_validation_requests
                else None
            ),
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

    def _plan_validation_requests(
        self,
        *,
        findings,
        target: str | None,
        method: ValidationMethod,
    ) -> list[ValidationRequest]:
        """Build validation requests from scanner findings."""
        if not target:
            return []

        plan = self.validation_planner.plan(
            findings,
            target=target,
            method=method,
        )

        return list(plan.requests)
