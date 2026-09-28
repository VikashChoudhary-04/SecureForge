```python id="4v8n2k"
"""Execution helpers for SecureForge validation and retesting."""

from __future__ import annotations

from dataclasses import dataclass

from .models import (
    RetestResult,
    ValidationOutcome,
    ValidationRequest,
    ValidationResult,
    ValidationSummary,
)
from .retest import RetestService
from .service import ValidationService


@dataclass(frozen=True)
class ValidationRun:
    """Result of a batch validation execution."""

    summary: ValidationSummary

    @property
    def results(self) -> list[ValidationResult]:
        """Return validation results."""
        return self.summary.results

    @property
    def successful(self) -> bool:
        """Return whether validation completed without errors."""
        return self.summary.errors == 0


@dataclass(frozen=True)
class RetestRun:
    """Result of a batch retesting execution."""

    results: list[RetestResult]

    @property
    def total(self) -> int:
        """Return the number of retested findings."""
        return len(self.results)

    @property
    def fixed(self) -> int:
        """Return the number of findings with verified remediation."""
        return sum(
            result.remediation_verified
            for result in self.results
        )

    @property
    def still_confirmed(self) -> int:
        """Return the number of findings still confirmed."""
        return sum(
            result.current_outcome == ValidationOutcome.CONFIRMED
            for result in self.results
        )

    @property
    def inconclusive(self) -> int:
        """Return the number of inconclusive retests."""
        return sum(
            result.current_outcome
            == ValidationOutcome.INCONCLUSIVE
            for result in self.results
        )

    @property
    def errors(self) -> int:
        """Return the number of retest errors."""
        return sum(
            result.current_outcome == ValidationOutcome.ERROR
            for result in self.results
        )

    @property
    def regression_required(self) -> bool:
        """Return whether any finding remains confirmed."""
        return any(
            result.regression_required
            for result in self.results
        )


class ValidationRunner:
    """Run validation and retesting workflows."""

    def __init__(
        self,
        validation_service: ValidationService,
        retest_service: RetestService | None = None,
    ) -> None:
        self.validation_service = validation_service
        self.retest_service = (
            retest_service
            or RetestService(validation_service)
        )

    def run(
        self,
        requests: list[ValidationRequest],
    ) -> ValidationRun:
        """Run validation requests in order."""
        summary = self.validation_service.validate_many(
            requests
        )

        return ValidationRun(
            summary=summary,
        )

    def retest(
        self,
        requests: list[
            tuple[ValidationRequest, ValidationOutcome]
        ],
    ) -> RetestRun:
        """Run retesting requests in order."""
        results = self.retest_service.retest_many(
            requests
        )

        return RetestRun(
            results=results,
        )
```
