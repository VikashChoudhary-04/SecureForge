"""Normalization pipeline for SecureForge evidence processing."""

from **future** import annotations

from collections.abc import Iterable

from .models import NormalizationResult, RawEvidence
from .registry import NormalizationRegistry

class NormalizationPipeline:
"""Normalize raw security evidence using registered adapters."""

```
def __init__(
    self,
    registry: NormalizationRegistry,
) -> None:
    self.registry = registry

def normalize(
    self,
    raw_evidence: RawEvidence,
) -> NormalizationResult:
    """Normalize one raw evidence object."""
    adapter = self.registry.get(
        raw_evidence.source
    )

    if adapter is None:
        return NormalizationResult(
            source=raw_evidence.source,
            evidence=[raw_evidence],
            success=False,
            errors=[
                (
                    "No normalization adapter is registered "
                    f"for source '{raw_evidence.source}'."
                )
            ],
        )

    try:
        result = adapter.parse(raw_evidence)

    except Exception as exc:
        return NormalizationResult(
            source=raw_evidence.source,
            evidence=[raw_evidence],
            success=False,
            errors=[
                (
                    f"Normalization adapter "
                    f"'{raw_evidence.source}' failed: {exc}"
                )
            ],
        )

    if not result.evidence:
        result.evidence.append(raw_evidence)

    return result

def normalize_many(
    self,
    evidence_items: Iterable[RawEvidence],
) -> list[NormalizationResult]:
    """Normalize multiple raw evidence objects."""
    return [
        self.normalize(raw_evidence)
        for raw_evidence in evidence_items
    ]

def aggregate(
    self,
    results: Iterable[NormalizationResult],
) -> NormalizationResult:
    """Aggregate multiple normalization results."""
    result_list = list(results)

    sources = [
        result.source
        for result in result_list
        if result.source
    ]

    source = ",".join(
        dict.fromkeys(sources)
    )

    findings: list[dict] = []
    evidence: list[RawEvidence] = []
    warnings: list[str] = []
    errors: list[str] = []

    for result in result_list:
        findings.extend(result.findings)
        evidence.extend(result.evidence)
        warnings.extend(result.warnings)
        errors.extend(result.errors)

    success = all(
        result.success
        for result in result_list
    )

    return NormalizationResult(
        source=source,
        findings=findings,
        evidence=evidence,
        warnings=warnings,
        errors=errors,
        success=success,
    )
```
