"""Remediation retesting for SecureForge."""

from __future__ import annotations

from .models import (
    RetestResult,
    ValidationOutcome,
    ValidationRequest,
)
from .service import ValidationService


class RetestService:
    """Retest previously identified findings after remediation."""

    def __init__(
        self,
        validation_service: ValidationService,
    ) -> None:
        self.validation_service = validation_service

    def retest(
        self,
        request: ValidationRequest,
        previous_outcome: ValidationOutcome,
    ) -> RetestResult:
        """Retest a finding and determine whether remediation succeeded."""
        validation = self.validation_service.validate(request)

        remediation_verified = (
            previous_outcome == ValidationOutcome.CONFIRMED
            and validation.outcome == ValidationOutcome.REJECTED
        )

        if remediation_verified:
            message = (
                "Retest indicates that the previously confirmed "
                "finding is no longer reproducible."
            )
        elif validation.outcome == ValidationOutcome.CONFIRMED:
            message = (
                "Retest confirms that the security finding remains "
                "reproducible."
            )
        elif validation.outcome == ValidationOutcome.REJECTED:
            message = (
                "Retest did not reproduce the security finding."
            )
        elif validation.outcome == ValidationOutcome.INCONCLUSIVE:
            message = (
                "Retest was inconclusive and remediation cannot "
                "yet be verified."
            )
        else:
            message = (
                "Retest encountered an error and remediation "
                "cannot be verified."
            )

        return RetestResult(
            finding_id=request.finding_id,
            previous_outcome=previous_outcome,
            current_outcome=validation.outcome,
            remediation_verified=remediation_verified,
            message=message,
            validation=validation,
        )

    def retest_many(
        self,
        requests: list[tuple[ValidationRequest, ValidationOutcome]],
    ) -> list[RetestResult]:
        """Retest multiple findings while preserving request order."""
        return [
            self.retest(
                request=request,
                previous_outcome=previous_outcome,
            )
            for request, previous_outcome in requests
        ]

