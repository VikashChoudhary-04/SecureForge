"""Normalize scan tool results into SecureForge findings."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from secureforge.core.normalization import NormalizationPipeline
from secureforge.core.normalization.models import (
    NormalizationResult,
    RawEvidence,
)

from .models import ToolExecutionResult


class ScanResultNormalizer:
    """Convert tool execution results into normalized SecureForge findings."""

    def __init__(
        self,
        pipeline: NormalizationPipeline | None = None,
        finding_factory: Any | None = None,
    ) -> None:
        self.pipeline = pipeline or NormalizationPipeline()

        if finding_factory is None:
            from secureforge.core.findings.factory import FindingFactory

            finding_factory = FindingFactory()

        self.finding_factory = finding_factory

    def build_evidence(
        self,
        result: ToolExecutionResult,
        *,
        target: str | None = None,
        application: str = "unknown",
    ) -> RawEvidence:
        """Convert tool execution output into raw normalization evidence."""
        metadata = dict(result.metadata)

        metadata.setdefault(
            "application",
            application,
        )

        raw_data = {
            "tool_name": result.tool_name,
            "integration": result.integration,
            "status": result.status.value,
            "command": result.command,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.exit_code,
        }

        error = getattr(result, "error", None)

        if error is not None:
            raw_data["error"] = error

        collected_at = (
            result.completed_at
            or result.started_at
            or datetime.now(timezone.utc)
        )

        return RawEvidence(
            source=result.integration,
            source_version=metadata.get("source_version"),
            target=target,
            collected_at=collected_at,
            raw_data=raw_data,
            metadata=metadata,
        )

    def normalize_result(
        self,
        result: ToolExecutionResult,
        *,
        target: str | None = None,
        application: str = "unknown",
    ) -> NormalizationResult:
        """Normalize one tool execution result."""
        return self._normalize_result(
            result,
            target=target,
            application=application,
        )

    def normalize_results(
        self,
        results: list[ToolExecutionResult],
        *,
        target: str | None = None,
        application: str = "unknown",
    ) -> list[NormalizationResult]:
        """Normalize multiple tool execution results."""
        return [
            self.normalize_result(
                result,
                target=target,
                application=application,
            )
            for result in results
        ]

    def findings_from_result(
        self,
        result: ToolExecutionResult,
        *,
        target: str | None = None,
        application: str = "unknown",
    ) -> tuple[NormalizationResult, list[Any]]:
        """Normalize one result and create canonical findings."""
        normalization_result = self.normalize_result(
            result,
            target=target,
            application=application,
        )

        if not normalization_result.success:
            return normalization_result, []

        findings = self.finding_factory.create_many(
            normalization_result.findings
        )

        return normalization_result, findings

    def findings_from_results(
        self,
        results: list[ToolExecutionResult],
        *,
        target: str | None = None,
        application: str = "unknown",
    ) -> tuple[list[NormalizationResult], list[Any]]:
        """Normalize successful tool results and create findings."""
        normalization_results: list[NormalizationResult] = []
        findings: list[Any] = []

        for result in results:
            if not result.succeeded:
                continue

            normalization_result, result_findings = (
                self.findings_from_result(
                    result,
                    target=target,
                    application=application,
                )
            )

            normalization_results.append(
                normalization_result
            )
            findings.extend(result_findings)

        return normalization_results, findings

    def normalize(
        self,
        result: ToolExecutionResult,
        *,
        target: str | None = None,
        application: str = "unknown",
    ) -> NormalizationResult:
        """Compatibility alias for normalize_result."""
        return self.normalize_result(
            result,
            target=target,
            application=application,
        )

    def _normalize_result(
        self,
        result: ToolExecutionResult,
        *,
        target: str | None,
        application: str,
    ) -> NormalizationResult:
        """Convert one tool result into a normalization result."""
        evidence = self.build_evidence(
            result,
            target=target,
            application=application,
        )

        try:
            return self.pipeline.normalize(
                evidence
            )
        except (AttributeError, TypeError, ValueError) as exc:
            return NormalizationResult(
                source=result.integration,
                evidence=[evidence],
                success=False,
                errors=[
                    f"Normalization failed: {exc}"
                ],
            )
