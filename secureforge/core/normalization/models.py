"""Models used during security evidence normalization."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc)


class RawEvidence(BaseModel):
    """Raw output collected from an external security source."""

    model_config = ConfigDict(extra="allow")

    source: str
    source_version: str | None = None
    source_reference: str | None = None

    target: str | None = None

    collected_at: datetime = Field(default_factory=utc_now)

    raw_data: Any

    metadata: dict[str, Any] = Field(default_factory=dict)


class NormalizationResult(BaseModel):
    """Result produced by a normalization adapter."""

    model_config = ConfigDict(extra="allow")

    source: str

    findings: list[dict[str, Any]] = Field(default_factory=list)

    evidence: list[RawEvidence] = Field(default_factory=list)

    warnings: list[str] = Field(default_factory=list)

    errors: list[str] = Field(default_factory=list)

    success: bool = True

    normalized_at: datetime = Field(default_factory=utc_now)

    @classmethod
    def success_result(
        cls,
        *,
        source: str,
        findings: list[dict[str, Any]] | None = None,
        evidence: list[RawEvidence] | None = None,
        warnings: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> "NormalizationResult":
        return cls(
            source=source,
            findings=list(findings or []),
            evidence=list(evidence or []),
            warnings=list(warnings or []),
            metadata=dict(metadata or {}),
            success=True,
        )

    @classmethod
    def failure(
        cls,
        *,
        source: str,
        errors: list[str] | None = None,
        findings: list[dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> "NormalizationResult":
        return cls(
            source=source,
            findings=list(findings or []),
            errors=list(errors or []),
            metadata=dict(metadata or {}),
            success=False,
        )

    @property
    def finding_count(self) -> int:
        """Return the number of normalized findings."""
        return len(self.findings)

    @property
    def has_errors(self) -> bool:
        """Return whether normalization produced errors."""
        return bool(self.errors)
