"""Core finding models for SecureForge."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import Any

from pydantic import BaseModel, Field, model_validator


def utc_now() -> datetime:
    """Return the current UTC timestamp."""
    return datetime.now(UTC)


class Severity(StrEnum):
    """Finding severity."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    """Confidence level of a finding."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class FindingStatus(StrEnum):
    """Lifecycle status of a finding."""

    OPEN = "open"
    VALIDATED = "validated"
    REJECTED = "rejected"
    REMEDIATED = "remediated"
    VERIFIED = "verified"


class ValidationStatus(StrEnum):
    """Validation status of a finding."""

    NOT_VALIDATED = "not_validated"
    INCONCLUSIVE = "inconclusive"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class Evidence(BaseModel):
    """Evidence supporting a finding."""

    evidence_id: str = ""
    source: str
    evidence_type: str = ""
    collected_at: datetime = Field(
        default_factory=utc_now
    )
    data: dict[str, Any] = Field(
        default_factory=dict
    )

    @model_validator(mode="before")
    @classmethod
    def normalize_legacy_fields(
        cls,
        value: Any,
    ) -> Any:
        """Normalize legacy evidence fields into the current model."""
        if not isinstance(value, dict):
            return value

        normalized = dict(value)

        evidence_type = normalized.get(
            "evidence_type"
        )

        if not evidence_type:
            evidence_type = normalized.get(
                "type"
            )

        if evidence_type:
            normalized["evidence_type"] = evidence_type

        evidence_id = normalized.get(
            "evidence_id"
        )

        if not evidence_id:
            evidence_id = cls._generate_evidence_id(
                normalized
            )

        normalized["evidence_id"] = evidence_id

        data = normalized.get("data")

        if not isinstance(data, dict):
            data = {}

        if "content" in normalized:
            data.setdefault(
                "content",
                normalized["content"],
            )

        if "location" in normalized:
            data.setdefault(
                "location",
                normalized["location"],
            )

        normalized["data"] = data

        return normalized

    @staticmethod
    def _generate_evidence_id(
        value: dict[str, Any],
    ) -> str:
        """Generate a deterministic identifier for evidence."""
        source = str(
            value.get(
                "source",
                "",
            )
        )
        evidence_type = str(
            value.get(
                "evidence_type",
                value.get(
                    "type",
                    "",
                ),
            )
        )
        content = str(
            value.get(
                "content",
                "",
            )
        )
        location = str(
            value.get(
                "location",
                "",
            )
        )

        canonical = "|".join(
            [
                source,
                evidence_type,
                content,
                location,
            ]
        )

        return (
            "evidence-"
            + sha256(
                canonical.encode("utf-8")
            ).hexdigest()[:16]
        )


class Finding(BaseModel):
    """Normalized security finding."""

    finding_id: str
    title: str
    source: str
    asset: str
    application: str = "SecureCommerce"
    endpoint: str | None = None
    parameter: str | None = None
    cwe: str | None = None
    owasp: str | None = None
    security_requirement: str | None = None
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.MEDIUM
    evidence: list[Evidence] = Field(
        default_factory=list
    )
    description: str = ""
    impact: str = ""
    remediation: str = ""
    status: FindingStatus = FindingStatus.OPEN
    validation_status: ValidationStatus = (
        ValidationStatus.NOT_VALIDATED
    )
    first_seen: datetime = Field(
        default_factory=utc_now
    )
    last_seen: datetime = Field(
        default_factory=utc_now
    )
    correlation_ids: list[str] = Field(
        default_factory=list
    )
    regression_test: str | None = None
    metadata: dict[str, Any] = Field(
        default_factory=dict
    )

    def add_evidence(
        self,
        evidence: Evidence | dict[str, Any],
    ) -> None:
        """Attach supporting evidence."""
        if isinstance(evidence, dict):
            evidence = Evidence.model_validate(
                evidence
            )

        self.evidence.append(evidence)
        self.last_seen = utc_now()

    def add_correlation(
        self,
        correlation_id: str,
    ) -> None:
        """Attach a correlation identifier."""
        if correlation_id not in self.correlation_ids:
            self.correlation_ids.append(
                correlation_id
            )

    def mark_validated(self) -> None:
        """Mark the finding as validated."""
        self.validation_status = (
            ValidationStatus.CONFIRMED
        )
        self.status = FindingStatus.VALIDATED
        self.last_seen = utc_now()

    def mark_rejected(self) -> None:
        """Mark the finding as rejected."""
        self.validation_status = (
            ValidationStatus.REJECTED
        )
        self.status = FindingStatus.REJECTED
        self.last_seen = utc_now()

    def mark_remediated(self) -> None:
        """Mark the finding as remediated."""
        self.status = FindingStatus.REMEDIATED
        self.last_seen = utc_now()

    def mark_verified(self) -> None:
        """Mark a remediated finding as verified."""
        self.status = FindingStatus.VERIFIED
        self.last_seen = utc_now()

    def reopen(self) -> None:
        """Reopen a previously closed finding."""
        self.status = FindingStatus.OPEN
        self.validation_status = (
            ValidationStatus.INCONCLUSIVE
        )
        self.last_seen = utc_now()
