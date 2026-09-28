"""Validation and retesting models for SecureForge."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class ValidationOutcome(str, Enum):
    """Possible outcomes of security validation."""

    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class ValidationMethod(str, Enum):
    """Methods used to validate a security finding."""

    HTTP = "http"
    API = "api"
    COMMAND = "command"
    SCRIPT = "script"
    MANUAL = "manual"


class ValidationEvidence(BaseModel):
    """Evidence produced by a validation attempt."""

    model_config = ConfigDict(
        extra="forbid"
    )

    method: ValidationMethod
    description: str
    request: str | None = None
    response: str | None = None
    command: str | None = None
    output: str | None = None
    expected: str | None = None
    observed: str | None = None


class ValidationResult(BaseModel):
    """Result of validating a security finding."""

    model_config = ConfigDict(
        extra="forbid"
    )

    finding_id: str
    outcome: ValidationOutcome
    message: str
    evidence: list[ValidationEvidence] = Field(
        default_factory=list
    )
    validator: str
    validated_at: str
    remediation_verified: bool = False

    @property
    def confirmed(self) -> bool:
        """Return whether the finding was confirmed."""
        return self.outcome == ValidationOutcome.CONFIRMED

    @property
    def rejected(self) -> bool:
        """Return whether the finding was rejected."""
        return self.outcome == ValidationOutcome.REJECTED

    @property
    def inconclusive(self) -> bool:
        """Return whether validation was inconclusive."""
        return self.outcome == ValidationOutcome.INCONCLUSIVE

    @property
    def failed(self) -> bool:
        """Return whether validation encountered an error."""
        return self.outcome == ValidationOutcome.ERROR


class ValidationRequest(BaseModel):
    """Request to validate a security finding."""

    model_config = ConfigDict(
        extra="forbid"
    )

    finding_id: str
    target: str
    method: ValidationMethod = ValidationMethod.HTTP
    endpoint: str | None = None
    parameter: str | None = None
    payload: str | None = None
    validator: str = "secureforge"
    metadata: dict[str, str] = Field(
        default_factory=dict
    )


class RetestResult(BaseModel):
    """Result of retesting a previously identified finding."""

    model_config = ConfigDict(
        extra="forbid"
    )

    finding_id: str
    previous_outcome: ValidationOutcome
    current_outcome: ValidationOutcome
    remediation_verified: bool
    message: str
    validation: ValidationResult

    @property
    def fixed(self) -> bool:
        """Return whether remediation appears effective."""
        return self.remediation_verified

    @property
    def regression_required(self) -> bool:
        """Return whether regression protection should remain active."""
        return self.current_outcome == ValidationOutcome.CONFIRMED


class ValidationSummary(BaseModel):
    """Aggregate validation results for a scan."""

    model_config = ConfigDict(
        extra="forbid"
    )

    total: int = 0
    confirmed: int = 0
    rejected: int = 0
    inconclusive: int = 0
    errors: int = 0
    remediated: int = 0
    results: list[ValidationResult] = Field(
        default_factory=list
    )

    @property
    def all_validated(self) -> bool:
        """Return whether every validation completed without error."""
        return (
            self.total > 0
            and self.errors == 0
            and (
                self.confirmed
                + self.rejected
                + self.inconclusive
            )
            == self.total
        )


__all__ = [
    "RetestResult",
    "ValidationEvidence",
    "ValidationMethod",
    "ValidationOutcome",
    "ValidationRequest",
    "ValidationResult",
    "ValidationSummary",
]
