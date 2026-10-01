"""Assessment helpers for SecureForge validation results."""

from __future__ import annotations

from dataclasses import dataclass

from .models import ValidationOutcome, ValidationResult


@dataclass(frozen=True)
class ValidationAssessment:
    """Derived state for a validation result."""

    finding_id: str
    outcome: ValidationOutcome
    confirmed: bool
    rejected: bool
    inconclusive: bool
    errored: bool
    remediation_verified: bool
    regression_required: bool
    status: str
    reason: str

    @property
    def actionable(self) -> bool:
        """Return whether the finding still requires security action."""
        return self.confirmed or self.inconclusive or self.errored

    @property
    def resolved(self) -> bool:
        """Return whether remediation has been verified."""
        return self.remediation_verified


def assess_validation(result: ValidationResult) -> ValidationAssessment:
    confirmed = result.outcome == ValidationOutcome.CONFIRMED
    rejected = result.outcome == ValidationOutcome.REJECTED
    inconclusive = result.outcome == ValidationOutcome.INCONCLUSIVE
    errored = result.outcome == ValidationOutcome.ERROR
    remediation_verified = (
        result.remediation_verified and rejected
    )

    if remediation_verified:
        status = "remediated"
        reason = (
            "The previously identified finding was not reproduced during "
            "retesting and remediation was explicitly verified."
        )
    elif confirmed:
        status = "confirmed"
        reason = (
            "The security finding was reproduced during validation "
            "and remains actionable."
        )
    elif rejected:
        status = "rejected"
        reason = (
            "The security finding was not reproduced during validation, "
            "but remediation was not explicitly verified."
        )
    elif inconclusive:
        status = "inconclusive"
        reason = (
            "Validation completed without enough evidence to confirm "
            "or reject the finding."
        )
    else:
        status = "error"
        reason = (
            "Validation could not be completed successfully. "
            "The finding requires another validation attempt."
        )

    return ValidationAssessment(
        finding_id=result.finding_id,
        outcome=result.outcome,
        confirmed=confirmed,
        rejected=rejected,
        inconclusive=inconclusive,
        errored=errored,
        remediation_verified=remediation_verified,
        regression_required=confirmed,
        status=status,
        reason=reason,
    )


def assess_many(
    results: list[ValidationResult],
) -> list[ValidationAssessment]:
    """Assess validation results in input order."""
    return [assess_validation(result) for result in results]


__all__ = [
    "ValidationAssessment",
    "assess_many",
    "assess_validation",
]
