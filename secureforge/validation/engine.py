```python id="684q2p"
"""Validation engine for SecureForge."""

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
from .registry import ValidatorRegistry, ValidatorRegistryError


class ValidationEngine:
    """Coordinate security finding validation."""

    def __init__(
        self,
        registry: ValidatorRegistry,
    ) -> None:
        self.registry = registry

    def validate(
        self,
        request: ValidationRequest,
    ) -> ValidationResult:
        """Resolve a validator and validate the requested finding."""
        validator = self._resolve_validator(request)

        try:
            return validator.validate(request)
        except ValidationError as exc:
            return self._error_result(
                request=request,
                validator=validator,
                message=str(exc),
            )
        except Exception as exc:
            return self._error_result(
                request=request,
                validator=validator,
                message=(
                    "Unexpected validation error: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

    def validate_many(
        self,
        requests: list[ValidationRequest],
    ) -> list[ValidationResult]:
        """Validate multiple findings in request order."""
        return [
            self.validate(request)
            for request in requests
        ]

    def _resolve_validator(
        self,
        request: ValidationRequest,
    ) -> BaseValidator:
        """Resolve a named validator or find one by request method."""
        requested_validator = request.validator.strip()

        if requested_validator != "secureforge":
            try:
                return self.registry.get(requested_validator)
            except ValidatorRegistryError:
                pass

        return self.registry.find(request)

    @staticmethod
    def _error_result(
        *,
        request: ValidationRequest,
        validator: BaseValidator,
        message: str,
    ) -> ValidationResult:
        """Build a structured validation error."""
        return ValidationResult(
            finding_id=request.finding_id,
            outcome=ValidationOutcome.ERROR,
            message=message,
            evidence=[
                ValidationEvidence(
                    method=request.method,
                    description="Security validation error.",
                    observed=message,
                )
            ],
            validator=validator.name,
            validated_at=datetime.now(timezone.utc).isoformat(),
        )

    def describe(self) -> list[dict[str, object]]:
        """Return metadata for all registered validators."""
        return [
            validator.describe()
            for validator in self.registry.list()
        ]

    def supports_method(
        self,
        method: ValidationMethod,
    ) -> bool:
        """Return whether a validator exists for a validation method."""
        request = ValidationRequest(
            finding_id="VALIDATION-CHECK",
            target="http://localhost",
            method=method,
        )

        try:
            self.registry.find(request)
        except ValidatorRegistryError:
            return False

        return True
```
