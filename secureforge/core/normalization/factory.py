"""Factory for converting normalization results into SecureForge findings."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from secureforge.core.findings import Finding, FindingFactory

from .models import NormalizationResult


class NormalizationFindingFactory:
    """Convert normalized finding dictionaries into canonical Finding objects."""

    def __init__(self, finding_factory: FindingFactory | None = None) -> None:
        self.finding_factory = finding_factory or FindingFactory()

    def create(self, result: NormalizationResult) -> list[Finding]:
        if not result.success:
            raise ValueError(
                "Cannot create findings from an unsuccessful normalization result."
            )
        return self.create_from_data(result.findings)

    def create_many(self, results: Iterable[NormalizationResult]) -> list[Finding]:
        findings: list[Finding] = []
        for result in results:
            findings.extend(self.create(result))
        return findings

    def create_from_data(self, findings: list[dict[str, Any]]) -> list[Finding]:
        created: list[Finding] = []
        for finding in findings:
            try:
                created.append(self.finding_factory.create(finding))
            except ValueError as exc:
                if str(exc).startswith("Missing required finding fields"):
                    raise
                raise
        return created


__all__ = ["NormalizationFindingFactory"]
