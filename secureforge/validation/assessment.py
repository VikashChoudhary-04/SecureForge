"""Assessment helpers for SecureForge validation results."""

from collections import namedtuple

from .models import ValidationOutcome, ValidationResult

ValidationAssessment = namedtuple(
"ValidationAssessment",
(
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
),
)

assess_validation = lambda result: (
lambda outcome, confirmed, rejected, inconclusive, errored, remediation_verified, regression_required: (
ValidationAssessment(
result.finding_id,
outcome,
confirmed,
rejected,
inconclusive,
errored,
remediation_verified,
regression_required,
"remediated" if remediation_verified else (
"confirmed" if confirmed else (
"rejected" if rejected else (
"inconclusive" if inconclusive else "error"
)
)
),
"The previously identified finding was not reproduced during retesting and remediation was explicitly verified."
if remediation_verified else (
"The security finding was reproduced during validation and remains actionable."
if confirmed else (
"The security finding was not reproduced during validation, but remediation was not explicitly verified."
if rejected else (
"Validation completed without enough evidence to confirm or reject the finding."
if inconclusive else
"Validation could not be completed successfully. The finding requires another validation attempt."
)
)
),
)
)
)(
result.outcome,
result.outcome == ValidationOutcome.CONFIRMED,
result.outcome == ValidationOutcome.REJECTED,
result.outcome == ValidationOutcome.INCONCLUSIVE,
result.outcome == ValidationOutcome.ERROR,
result.remediation_verified and result.outcome == ValidationOutcome.REJECTED,
result.outcome == ValidationOutcome.CONFIRMED,
)

assess_many = lambda results: [assess_validation(result) for result in results]
