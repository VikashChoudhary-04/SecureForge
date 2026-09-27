"""Scan-result normalization bridge for SecureForge."""

from **future** import annotations

from typing import Any

from secureforge.core.normalization import (
NormalizationFindingFactory,
NormalizationPipeline,
RawEvidence,
)

from .models import ToolExecutionResult

class ScanResultNormalizer:
"""Convert tool execution results into normalized SecureForge findings."""

```
def __init__(
    self,
    pipeline: NormalizationPipeline,
    finding_factory: NormalizationFindingFactory | None = None,
) -> None:
    self.pipeline = pipeline
    self.finding_factory = (
        finding_factory
        or NormalizationFindingFactory()
    )

def build_evidence(
    self,
    result: ToolExecutionResult,
    *,
    target: str | None = None,
    application: str | None = None,
) -> RawEvidence:
    """Convert one tool result into raw SecureForge evidence."""
    raw_data: dict[str, Any] = {
        "tool_name": result.tool_name,
        "integration": result.integration,
        "status": result.status.value,
        "command": result.command,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "duration_seconds": result.duration_seconds,
        "error": result.error,
    }

    metadata = dict(result.metadata)

    if application is not None:
        metadata.setdefault(
            "application",
            application,
        )

    return RawEvidence(
        source=result.integration,
        source_version=metadata.get(
            "source_version"
        ),
        source_reference=result.evidence_path,
        target=target,
        collected_at=(
            result.completed_at
            or result.started_at
        ),
        raw_data=raw_data,
        metadata=metadata,
    )

def normalize_result(
    self,
    result: ToolExecutionResult,
    *,
    target: str | None = None,
    application: str | None = None,
):
    """Normalize one tool execution result."""
    evidence = self.build_evidence(
        result,
        target=target,
        application=application,
    )

    return self.pipeline.normalize(
        evidence
    )

def findings_from_result(
    self,
    result: ToolExecutionResult,
    *,
    target: str | None = None,
    application: str | None = None,
):
    """Normalize a result and create canonical findings."""
    normalization_result = self.normalize_result(
        result,
        target=target,
        application=application,
    )

    if not normalization_result.success:
        return normalization_result, []

    findings = self.finding_factory.create(
        normalization_result
    )

    return normalization_result, findings

def normalize_results(
    self,
    results: list[ToolExecutionResult],
    *,
    target: str | None = None,
    application: str | None = None,
):
    """Normalize multiple tool execution results."""
    evidence_items = [
        self.build_evidence(
            result,
            target=target,
            application=application,
        )
        for result in results
    ]

    return self.pipeline.normalize_many(
        evidence_items
    )

def findings_from_results(
    self,
    results: list[ToolExecutionResult],
    *,
    target: str | None = None,
    application: str | None = None,
):
    """Normalize multiple results and create canonical findings."""
    normalization_results = self.normalize_results(
        results,
        target=target,
        application=application,
    )

    findings = self.finding_factory.create_many(
        result
        for result in normalization_results
        if result.success
    )

    return normalization_results, findings
```
