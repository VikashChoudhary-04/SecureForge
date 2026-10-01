"""Normalize scan tool results into SecureForge findings."""

from __future__ import annotations

from typing import Any

from secureforge.core.normalization import NormalizationPipeline
from secureforge.core.normalization.models import NormalizationResult

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

    def findings_from_results(
        self,
        results: list[ToolExecutionResult],
        *,
        target: str | None = None,
        application: str = "unknown",
    ) -> tuple[list[NormalizationResult], list[Any]]:
        """Normalize successful tool results into findings."""
        normalization_results: list[NormalizationResult] = []
        findings: list[Any] = []

        for result in results:
            if not result.succeeded:
                continue

            normalized = self._normalize_result(
                result,
                target=target,
                application=application,
            )

            normalization_results.append(normalized)

            if normalized.success:
                findings.extend(
                    self.finding_factory.create_many(
                        normalized.findings
                    )
                )

        return normalization_results, findings

    def normalize(
        self,
        result: ToolExecutionResult,
        *,
        target: str | None = None,
        application: str = "unknown",
    ) -> NormalizationResult:
        """Normalize one successful tool execution result."""
        return self._normalize_result(
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
        """Convert one tool result into normalized evidence."""
        metadata = dict(result.metadata)

        metadata.setdefault(
            "tool_name",
            result.tool_name,
        )
        metadata.setdefault(
            "integration",
            result.integration,
        )
        metadata.setdefault(
            "application",
            application,
        )

        try:
            return self.pipeline.normalize(
                source=result.integration,
                raw_data={
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "exit_code": result.exit_code,
                    "command": result.command,
                    "target": target,
                },
                target=target,
                metadata=metadata,
            )
        except (AttributeError, TypeError):
            return self._fallback_normalization(
                result,
                target=target,
                application=application,
            )

    @staticmethod
    def _fallback_normalization(
        result: ToolExecutionResult,
        *,
        target: str | None,
        application: str,
    ) -> NormalizationResult:
        """Return a safe empty normalization result when no adapter exists."""
        return NormalizationResult(
            source=result.integration,
            findings=[],
            warnings=[
                (
                    f"No normalization adapter is available for "
                    f"integration '{result.integration}'."
                )
            ],
            errors=[],
            success=True,
            evidence=[],
            metadata={
                "tool_name": result.tool_name,
                "application": application,
                "target": target,
            },
        )
