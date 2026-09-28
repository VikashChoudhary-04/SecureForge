"""Factory for converting normalization results into SecureForge findings."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from secureforge.core.findings import Finding

from .models import NormalizationResult


class NormalizationFindingFactory:
    """Convert normalized finding dictionaries into Finding objects."""

    def create(
        self,
        result: NormalizationResult,
    ) -> list[Finding]:
        """Create canonical findings from one normalization result."""
        if not result.success:
            raise ValueError(
                "Cannot create findings from an unsuccessful "
                "normalization result."
            )

        return self.create_from_data(
            result.findings
        )

    def create_many(
        self,
        results: Iterable[NormalizationResult],
    ) -> list[Finding]:
        """Create canonical findings from multiple results."""
        findings: list[Finding] = []

        for result in results:
            findings.extend(
                self.create(result)
            )

        return findings

    def create_from_data(
        self,
        findings: list[dict[str, Any]],
    ) -> list[Finding]:
        """Create canonical findings from normalized dictionaries."""
        return [
            Finding.model_validate(
                finding
            )
            for finding in findings
        ]
