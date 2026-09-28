```python id="9k4m2p"
"""Service layer for SecureForge validation and retesting."""

from __future__ import annotations

from .assessment import assess_validation
from .engine import ValidationEngine
from .models import (
    RetestResult,
    ValidationRequest,
    ValidationResult,
    ValidationSummary,
)
from .planner import ValidationPlan, ValidationPlanner
from .retest import RetestService


class ValidationService:
    """Coordinate validation, planning and retesting."""

    def __init__(
        self,
        engine: ValidationEngine,
        *,
        planner: ValidationPlanner | None = None,
        retest_service: RetestService | None = None,
    ) -> None:
        self.engine = engine
        self.planner = (
            planner
            if planner is not None
            else ValidationPlanner()
        )
        self.retest_service = (
            retest_service
            if retest_service is not None
            else RetestService(self)
        )

    def validate(
        self,
        request: ValidationRequest,
    ) -> ValidationResult:
        """Validate one security finding."""
        return self.engine.validate(request)

    def validate_many(
        self,
        requests: list[ValidationRequest],
    ) -> ValidationSummary:
        """Validate multiple security findings."""
        results = [
            self.validate(request)
            for request in requests
        ]

        return self.summarize(results)

    def plan(
        self,
        findings,
        *,
        target: str,
        method,
    ) -> ValidationPlan:
        """Create validation requests from scan findings."""
        return self.planner.plan(
            findings,
            target=target,
            method=method,
        )

    def validate_findings(
        self,
        findings,
        *,
        target: str,
        method,
    ) -> ValidationSummary:
        """Plan and validate eligible scan findings."""
        plan = self.plan(
            findings,
            target=target,
            method=method,
        )

        return self.validate_many(
            list(plan.requests)
        )

    def summarize(
        self,
        results: list[ValidationResult],
    ) -> ValidationSummary:
        """Build an aggregate validation summary."""
        confirmed = sum(
            result.confirmed
            for result in results
        )

        rejected = sum(
            result.rejected
            for result in results
        )

        inconclusive = sum(
            result.inconclusive
            for result in results
        )

        errors = sum(
            result.failed
            for result in results
        )

        remediated = sum(
            result.remediation_verified
            for result in results
        )

        return ValidationSummary(
            total=len(results),
            confirmed=confirmed,
            rejected=rejected,
            inconclusive=inconclusive,
            errors=errors,
            remediated=remediated,
            results=results,
        )

    def remediation_candidates(
        self,
        results: list[ValidationResult],
    ) -> list[ValidationResult]:
        """Return validation results indicating remediation."""
        return [
            result
            for result in results
            if result.remediation_verified
        ]

    def regression_candidates(
        self,
        results: list[ValidationResult],
    ) -> list[ValidationResult]:
        """Return confirmed findings suitable for regression creation."""
        return [
            result
            for result in results
            if result.confirmed
        ]

    def assessments(
        self,
        results: list[ValidationResult],
    ):
        """Build assessments for validation results."""
        return [
            assess_validation(result)
            for result in results
        ]

    def retest(
        self,
        request: ValidationRequest,
        previous_outcome,
    ) -> RetestResult:
        """Retest a previously validated finding."""
        return self.retest_service.retest(
            request,
            previous_outcome,
        )

    def retest_many(
        self,
        requests,
    ) -> list[RetestResult]:
        """Retest multiple findings."""
        return self.retest_service.retest_many(
            requests
        )


__all__ = [
    "ValidationService",
]
```
