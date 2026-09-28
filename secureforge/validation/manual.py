"""Manual security validation for SecureForge."""

from __future__ import annotations

from datetime import datetime, timezone

from .base import BaseValidator, ValidationError
from .models import (
    ValidationEvidence,
    ValidationMethod,
    ValidationOutcome,
    ValidationRequest,
    ValidationResult,
)


class ManualValidator(BaseValidator):
    """Record controlled analyst-provided validation evidence."""

    name = "manual"

    def supports(self, request: ValidationRequest) -> bool:
        """Return whether this validator supports manual validation."""
        return request.method == ValidationMethod.MANUAL

    def validate(self, request: ValidationRequest) -> ValidationResult:
        """Convert analyst-provided evidence into a validation result."""
        outcome_value = request.metadata.get("outcome")

        if not outcome_value:
            raise ValidationError(
                "Manual validation requires an outcome."
            )

        try:
            outcome = ValidationOutcome(outcome_value.lower())
        except ValueError as exc:
            allowed = ", ".join(
                item.value for item in ValidationOutcome
            )
            raise ValidationError(
                f"Invalid manual validation outcome: "
                f"{outcome_value}. Allowed values: {allowed}"
            ) from exc

        message = request.metadata.get("message")

        if not message:
            raise ValidationError(
                "Manual validation requires a message."
            )

        description = request.metadata.get(
            "description",
            "Analyst-provided security validation evidence.",
        )

        evidence = ValidationEvidence(
            method=ValidationMethod.MANUAL,
            description=description,
            request=request.metadata.get("request"),
            response=request.metadata.get("response"),
            command=request.metadata.get("command"),
            output=request.metadata.get("output"),
            expected=request.metadata.get("expected"),
            observed=request.metadata.get("observed"),
        )

        validated_at = datetime.now(timezone.utc).isoformat()

        remediation_verified = (
            request.metadata.get(
                "remediation_verified",
                "false",
            ).lower()
            == "true"
        )

        return ValidationResult(
            finding_id=request.finding_id,
            outcome=outcome,
            message=message,
            evidence=[evidence],
            validator=self.name,
            validated_at=validated_at,
            remediation_verified=remediation_verified,
        )
