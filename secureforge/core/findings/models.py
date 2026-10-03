"""Core finding models for SecureForge."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import Any

from pydantic import BaseModel, Field, model_validator


def utc_now() -> datetime:
    return datetime.now(UTC)


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class InformationalSeverity(StrEnum):
    INFORMATIONAL = "informational"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class FindingStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    VALIDATED = "validated"
    REJECTED = "rejected"
    REMEDIATED = "remediated"
    VERIFIED = "verified"
    ACCEPTED = "accepted"
    REOPENED = "reopened"


class ValidationStatus(StrEnum):
    NOT_VALIDATED = "not_validated"
    INCONCLUSIVE = "inconclusive"
    CONFIRMED = "confirmed"
    VALIDATED = "validated"
    VERIFIED = "verified"
    REJECTED = "rejected"


class Evidence(BaseModel):
    evidence_id: str = ""
    source: str
    evidence_type: str = ""
    source_reference: str | None = None
    description: str = ""
    collected_at: datetime = Field(default_factory=utc_now)
    data: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def normalize_legacy_fields(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        normalized = dict(value)
        normalized["evidence_type"] = normalized.get("evidence_type") or normalized.get("type") or ""
        if not normalized.get("evidence_id"):
            normalized["evidence_id"] = "evidence-" + cls._generate_evidence_id(normalized)
        data = normalized.get("data")
        if not isinstance(data, dict):
            data = {}
        if "content" in normalized:
            data.setdefault("content", normalized["content"])
        if "location" in normalized:
            data.setdefault("location", normalized["location"])
        normalized["data"] = data
        if not normalized.get("description"):
            normalized["description"] = str(data.get("content", ""))
        return normalized

    @staticmethod
    def _generate_evidence_id(value: dict[str, Any]) -> str:
        canonical = "|".join([
            str(value.get("source", "")),
            str(value.get("evidence_type", value.get("type", ""))),
            str(value.get("content", "")),
            str(value.get("location", "")),
        ])
        return sha256(canonical.encode("utf-8")).hexdigest()[:16]


class Finding(BaseModel):
    finding_id: str
    title: str
    source: str
    source_finding_id: str | None = None
    asset: str = ""
    application: str = "SecureCommerce"
    endpoint: str | None = None
    parameter: str | None = None
    cwe: str | None = None
    owasp: str | None = None
    owasp_mapping: str | None = None
    security_requirement: str | None = None
    severity: Severity | InformationalSeverity = Severity.INFO
    confidence: Confidence = Confidence.MEDIUM
    evidence: list[Evidence] = Field(default_factory=list)
    description: str = ""
    impact: str = ""
    remediation: str = ""
    status: FindingStatus = FindingStatus.OPEN
    validation_status: ValidationStatus = ValidationStatus.NOT_VALIDATED
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    correlation_ids: list[str] = Field(default_factory=list)
    regression_test: str | None = None
    scanner_rule_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def correlated_finding_ids(self) -> list[str]:
        return list(self.correlation_ids)

    @property
    def correlations(self) -> list[str]:
        return list(self.correlation_ids)

    def add_evidence(self, evidence: Evidence | dict[str, Any]) -> None:
        if isinstance(evidence, dict):
            evidence = Evidence.model_validate(evidence)
        self.evidence.append(evidence)
        self.last_seen = utc_now()

    def add_correlation(self, correlation_id: str) -> None:
        if correlation_id not in self.correlation_ids:
            self.correlation_ids.append(correlation_id)

    def mark_validated(self) -> None:
        self.validation_status = ValidationStatus.CONFIRMED
        self.confidence = Confidence.CONFIRMED
        self.status = FindingStatus.OPEN
        self.last_seen = utc_now()

    def mark_rejected(self) -> None:
        self.validation_status = ValidationStatus.REJECTED
        self.status = FindingStatus.OPEN
        self.last_seen = utc_now()

    def mark_remediated(self) -> None:
        self.status = FindingStatus.REMEDIATED
        self.last_seen = utc_now()

    def mark_verified(self) -> None:
        self.validation_status = ValidationStatus.CONFIRMED
        self.status = FindingStatus.VERIFIED
        self.last_seen = utc_now()

    def reopen(self) -> None:
        self.status = FindingStatus.REOPENED
        self.last_seen = utc_now()


__all__ = [
    "Confidence", "Evidence", "Finding", "FindingStatus",
    "InformationalSeverity", "Severity", "ValidationStatus",
]
