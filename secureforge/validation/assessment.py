"""Assessment helpers for SecureForge validation results."""

from dataclasses import dataclass

from .models import ValidationOutcome, ValidationResult

@dataclass(frozen=True)
class ValidationAssessment:
"""Interpretation of a security validation result."""


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
    def resolved(self) -> bool:
        """Return whether the finding has been resolved."""
        return self.remediation_verified
    
    @property
    def actionable(self) -> bool:
        """Return whether additional security action is required."""
        return self.confirmed or self.inconclusive or self.errored
    
    
    def assess_validation(result: ValidationResult) -> ValidationAssessment:
    """Convert a validation result into an actionable assessment."""
    outcome = result.outcome
    confirmed = outcome == ValidationOutcome.CONFIRMED
    rejected = outcome == ValidationOutcome.REJECTED
    inconclusive = outcome == ValidationOutcome.INCONCLUSIVE
    errored = outcome == ValidationOutcome.ERROR
    
    
    remediation_verified = result.remediation_verified and rejected
    regression_required = confirmed
    
    if remediation_verified:
        status = "remediated"
        reason = (
            "The previously identified finding was not reproduced "
            "during retesting and remediation was explicitly verified."
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
        outcome=outcome,
        confirmed=confirmed,
        rejected=rejected,
        inconclusive=inconclusive,
        errored=errored,
        remediation_verified=remediation_verified,
        regression_required=regression_required,
        status=status,
        reason=reason,
    )
    
    
    def assess_many(
    results: list[ValidationResult],
    ) -> list[ValidationAssessment]:
    """Assess multiple validation results in their original order."""
    return [assess_validation(result) for result in results]
