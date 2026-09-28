"""Assessment helpers for SecureForge validation results."""

from collections import namedtuple

from .models import ValidationOutcome, ValidationResult

ValidationAssessment = namedtuple(
"ValidationAssessment",
[
"finding_id",
"outcome",
"confirmed",
"rejected",
"inconclusive",
"errored",
"remediation_verified",
"regression_required",
"status",
"reason",
],
)

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
        result.finding_id,
        outcome,
        confirmed,
        rejected,
        inconclusive,
        errored,
        remediation_verified,
        regression_required,
        status,
        reason,
    )
