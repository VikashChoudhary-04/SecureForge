"""Scan orchestration for SecureForge."""

from __future__ import annotations

import inspect
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from secureforge.validation.models import ValidationMethod, ValidationRequest
from secureforge.validation.planner import ValidationPlanner

from .models import ScanConfiguration, ScanExecution, SecurityScanResult
from .runner import ScanRunner
from .security_pipeline import SecurityPipeline


class ScanOrchestrator:
    """Coordinate tool execution and security verification."""

    def __init__(
        self,
        *,
        runner: ScanRunner,
        pipeline: SecurityPipeline | None = None,
        validation_planner: ValidationPlanner | None = None,
    ) -> None:
        self.runner = runner
        self.pipeline = pipeline or SecurityPipeline()
        self.validation_planner = validation_planner or ValidationPlanner()

    def run(
        self,
        *,
        scan_id: str,
        profile: str,
        target: str | None = None,
        source_path: str | Path | None = None,
        application: str = "SecureCommerce",
        version: str = "1.0.0",
        commit_sha: str | None = None,
        environment: str = "lab",
        validation_requests: list[ValidationRequest] | None = None,
        validate_findings: bool = False,
        validation_method: ValidationMethod = ValidationMethod.HTTP,
        run_regression: bool = False,
        regression_result: Any | None = None,
        regression_gate: Any | None = None,
    ) -> SecurityScanResult:
        started_at = datetime.now(timezone.utc)

        execution = self._run_runner(
            scan_id=scan_id,
            profile=profile,
            target=target,
            source_path=source_path,
            application=application,
            version=version,
            commit_sha=commit_sha,
            environment=environment,
        )

        planned = (
            self._plan_validation_requests(
                findings=execution.findings,
                target=target,
                method=validation_method,
            )
            if validate_findings
            else []
        )

        effective_requests = (
            validation_requests
            if validation_requests is not None
            else planned
        )

        pipeline_result = self.pipeline.run(
            execution.findings,
            validation_requests=(
                effective_requests if effective_requests else None
            ),
            run_regression=run_regression,
            regression=regression_result,
            regression_gate=regression_gate,
        )

        completed_at = datetime.now(timezone.utc)

        scan_execution = ScanExecution(
            scan_id=scan_id,
            profile=profile,
            application=application,
            version=version,
            commit_sha=commit_sha,
            environment=environment,
            target=target or "secureforge-ci" if str(profile).lower() == "ci" else target,
            started_at=started_at.isoformat(),
            completed_at=completed_at.isoformat(),
            status=execution.status,
            tools=getattr(execution, "tools", []),
            tool_errors=getattr(execution, "tool_errors", []),
        )

        return SecurityScanResult(
            execution=scan_execution,
            findings=pipeline_result.findings,
            pipeline=pipeline_result,
            scan_id=scan_id,
            application=application,
            version=version,
            profile=profile,
            environment=environment,
            status=execution.status,
            commit_sha=commit_sha,
        )

    def _run_runner(self, **kwargs: Any):
        signature = inspect.signature(self.runner.run)
        parameters = signature.parameters

        if "configuration" in parameters:
            integrations = {}
            if str(kwargs["profile"]).lower() == "ci":
                integrations = {
                    "ci": {
                        "name": "ci",
                        "enabled": True,
                    }
                }

            configuration = ScanConfiguration(
                application=kwargs["application"],
                version=kwargs["version"],
                profile=kwargs["profile"],
                environment=kwargs["environment"],
                commit_sha=kwargs["commit_sha"],
                target=kwargs["target"],
                integrations=integrations,
                metadata={
                    "source_path": (
                        str(kwargs["source_path"])
                        if kwargs["source_path"] is not None
                        else None
                    ),
                },
            )
            result = self.runner.run(
                configuration,
                commit_sha=kwargs["commit_sha"],
            )
        else:
            accepted = {
                key: value
                for key, value in kwargs.items()
                if key in parameters
            }
            result = self.runner.run(**accepted)

        if kwargs.get("target") is not None:
            self._propagate_target(result, kwargs["target"])

        return result

    @staticmethod
    def _propagate_target(result: Any, target: str) -> None:
        if hasattr(result, "target"):
            try:
                result.target = target
            except Exception:
                pass

        execution = getattr(result, "execution", None)
        if execution is not None and hasattr(execution, "target"):
            try:
                execution.target = target
            except Exception:
                pass

    def _plan_validation_requests(
        self,
        *,
        findings: list[Any],
        target: str | None,
        method: ValidationMethod,
    ) -> list[ValidationRequest]:
        if not findings or target is None:
            return []
        try:
            return self.validation_planner.plan(
                findings,
                target=target,
                method=method,
            )
        except TypeError:
            return self.validation_planner.plan(findings, target)
