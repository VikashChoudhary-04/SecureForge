# Validation and retesting runner

from __future__ import annotations

from dataclasses import dataclass

from .models import (
    RetestResult,
    ValidationRequest,
    ValidationSummary,
)
from .retest import RetestService
from .service import ValidationService


@dataclass(frozen=True)
class ValidationRun:
    """Complete result of a validation run."""

    summary: ValidationSummary

    @property
    def results(self):
        """Return individual validation results."""
        return self.summary.results

    @property
    def total(self) -> int:
        """Return the number of validation attempts."""
        return self.summary.total

    @property
    def confirmed(self) -> int:
        """Return the number of confirmed findings."""
        return self.summary.confirmed

    @property
    def rejected(self) -> int:
        """Return the number of rejected findings."""
        return self.summary.rejected

    @property
    def inconclusive(self) -> int:
        """Return the number of inconclusive results."""
        return self.summary.inconclusive

    @property
    def errors(self) -> int:
        """Return the number of validation errors."""
        return self.summary.errors

    @property
    def successful(self) -> bool:
        """Return whether validation completed without errors."""
        return self.summary.errors == 0


@dataclass(frozen=True)
class RetestRun:
    """Complete result of a retest run."""

    results: list[RetestResult]

    @property
    def total(self) -> int:
        """Return the number of retests."""
        return len(self.results)

    @property
    def fixed(self) -> int:
        """Return the number of findings fixed."""
        return sum(
            result.fixed
            for result in self.results
        )

    @property
    def still_confirmed(self) -> int:
        """Return the number of findings still confirmed."""
        return sum(
            result.current_outcome.value
            == "confirmed"
            for result in self.results
        )

    @property
    def inconclusive(self) -> int:
        """Return the number of inconclusive retests."""
        return sum(
            result.current_outcome.value
            == "inconclusive"
            for result in self.results
        )

    @property
    def errors(self) -> int:
        """Return the number of retest errors."""
        return sum(
            result.current_outcome.value
            == "error"
            for result in self.results
        )

    @property
    def regression_required(self) -> bool:
        """Return whether any retest requires regression coverage."""
        return any(
            result.regression_required
            for result in self.results
        )


class ValidationRunner:
    """Execute validation and retesting workflows."""

    def __init__(
        self,
        validation_service: ValidationService,
        *,
        retest_service: RetestService | None = None,
    ) -> None:
        self.validation_service = (
            validation_service
        )

        self.retest_service = (
            retest_service
            if retest_service is not None
            else RetestService(
                validation_service
            )
        )

    def run(
        self,
        requests: list[ValidationRequest],
    ) -> ValidationRun:
        """Execute validation requests."""
        summary = (
            self.validation_service.validate_many(
                requests
            )
        )

        return ValidationRun(
            summary=summary
        )

    def retest(
        self,
        requests: list[
            tuple[
                ValidationRequest,
                object,
            ]
        ],
    ) -> RetestRun:
        """Execute retesting requests."""
        results: list[RetestResult] = []

        for request, previous_outcome in requests:
            results.append(
                self.retest_service.retest(
                    request,
                    previous_outcome,
                )
            )

        return RetestRun(
            results=results
        )


__all__ = [
    "RetestRun",
    "ValidationRun",
    "ValidationRunner",
]
