```python id="731d0p"
"""Validation service for SecureForge."""

from __future__ import annotations

from .engine import ValidationEngine
from .models import (
    ValidationOutcome,
    ValidationRequest,
    ValidationResult,
    ValidationSummary,
)


class ValidationService:
    """Provide application-level security validation operations."""

    def __init__(
        self,
        engine: ValidationEngine,
    ) -> None:
        self.engine = engine

    def validate(
        self,
        request: ValidationRequest,
    ) -> ValidationResult:
        """Validate a single security finding."""
        return self.engine.validate(request)

    def validate_many(
        self,
        requests: list[ValidationRequest],
    ) -> ValidationSummary:
        """Validate multiple findings and summarize their outcomes."""
        results = self.engine.validate_many(requests)
        return self.summarize(results)

    @staticmethod
    def summarize(
        results: list[ValidationResult],
    ) -> ValidationSummary:
        """Build an aggregate summary from validation results."""
        confirmed = 0
        rejected = 0
        inconclusive = 0
        errors = 0
        remediated = 0

        for result in results:
            if result.outcome == ValidationOutcome.CONFIRMED:
                confirmed += 1
            elif result.outcome == ValidationOutcome.REJECTED:
                rejected += 1
            elif result.outcome == ValidationOutcome.INCONCLUSIVE:
                inconclusive += 1
            elif result.outcome == ValidationOutcome.ERROR:
                errors += 1

            if result.remediation_verified:
                remediated += 1

        return ValidationSummary(
            total=len(results),
            confirmed=confirmed,
            rejected=rejected,
            inconclusive=inconclusive,
            errors=errors,
            remediated=remediated,
            results=results,
        )

    @staticmethod
    def remediation_candidates(
        results: list[ValidationResult],
    ) -> list[ValidationResult]:
        """Return findings whose remediation was verified."""
        return [
            result
            for result in results
            if result.remediation_verified
        ]

    @staticmethod
    def regression_candidates(
        results: list[ValidationResult],
    ) -> list[ValidationResult]:
        """Return confirmed findings that may require regression tests."""
        return [
            result
            for result in results
            if result.outcome == ValidationOutcome.CONFIRMED
        ]
```
