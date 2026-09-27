"""Base interface for SecureForge normalization adapters."""

from **future** import annotations

from abc import ABC, abstractmethod
from typing import Any

from .models import NormalizationResult, RawEvidence

class NormalizationAdapter(ABC):
"""Base class for converting external tool output into SecureForge data."""

```
source_name: str = "unknown"

def __init__(self, source_version: str | None = None) -> None:
    self.source_version = source_version

@abstractmethod
def parse(self, raw_evidence: RawEvidence) -> NormalizationResult:
    """Parse raw evidence into normalized security data."""
    raise NotImplementedError

def validate_input(self, raw_evidence: RawEvidence) -> None:
    """Validate basic adapter input before parsing."""
    if not raw_evidence.source:
        raise ValueError("Evidence source cannot be empty.")

    if raw_evidence.source != self.source_name:
        raise ValueError(
            f"Expected source '{self.source_name}', "
            f"received '{raw_evidence.source}'."
        )

def build_finding_data(
    self,
    *,
    finding_id: str,
    title: str,
    application: str,
    asset: str,
    severity: str,
    description: str,
    impact: str,
    remediation: str,
    **kwargs: Any,
) -> dict[str, Any]:
    """Build the common normalized finding representation."""
    finding: dict[str, Any] = {
        "finding_id": finding_id,
        "title": title,
        "source": self.source_name,
        "application": application,
        "asset": asset,
        "severity": severity,
        "description": description,
        "impact": impact,
        "remediation": remediation,
    }

    finding.update(kwargs)

    return finding
```
