"""Factory for converting normalization results into SecureForge findings."""

from **future** import annotations

from collections.abc import Iterable

from secureforge.core.findings import Finding, FindingFactory

from .models import NormalizationResult

class NormalizationFindingFactory:
"""Convert normalized finding dictionaries into Finding objects."""

```
def __init__(
    self,
    finding_factory: FindingFactory | None = None,
) -> None:
    self.finding_factory = (
        finding_factory
        or FindingFactory()
    )

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

    return self.finding_factory.create_many(
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
    findings: list[dict],
) -> list[Finding]:
    """Create canonical findings from normalized dictionaries."""
    return self.finding_factory.create_many(
        findings
    )
```
