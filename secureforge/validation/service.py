"""Service layer for SecureForge validation and retesting."""

from __future__ import annotations

from .assessment import assess_validation
from .engine import ValidationEngine
from .factory import build_validation_engine
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
        engine: ValidationEngine | None = None,
        *,
        planner: ValidationPlanner | None = None,
        retest_service: RetestService | None = None,
    ) -> None:
        self.engine = (
            engine
            if engine is not None
            else build_validation_engine()
        )
        self.planner = planner or ValidationPlanner()
        self.retest_service = (
            retest_service
            if retest_service is not None
            else RetestService(self)
        )

    def validate(
        self,
        request: ValidationRequest,
    ) -> ValidationResult:
        return self.engine.validate(request)

    def validate_many(
        self,
        requests: list[ValidationRequest],
    ) -> ValidationSummary:
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
        plan = self.plan(
            findings,
            target=target,
            method=method,
        )
        return self.validate_many(
            list(plan.requests)
        )

    @staticmethod
    def summarize(
        results: list[ValidationResult] | None = None,
    ) -> ValidationSummary:
        results = list(results or [])

        return ValidationSummary(
            total=len(results),
            confirmed=sum(
                result.confirmed
                for result in results
            ),
            rejected=sum(
                result.rejected
                for result in results
            ),
            inconclusive=sum(
                result.inconclusive
                for result in results
            ),
            errors=sum(
                result.failed
                for result in results
            ),
            remediated=sum(
                result.remediation_verified
                for result in results
            ),
            results=results,
        )

    @staticmethod
    def remediation_candidates(
        results: list[ValidationResult] | None = None,
    ) -> list[ValidationResult]:
        return [
            result
            for result in (results or [])
            if result.remediation_verified
        ]

    @staticmethod
    def regression_candidates(
        results: list[ValidationResult] | None = None,
    ) -> list[ValidationResult]:
        return [
            result
            for result in (results or [])
            if result.confirmed
        ]

    @staticmethod
    def assessments(
        results: list[ValidationResult],
    ):
        return [
            assess_validation(result)
            for result in results
        ]

    def retest(
        self,
        request: ValidationRequest,
        previous_outcome,
    ) -> RetestResult:
        return self.retest_service.retest(
            request,
            previous_outcome,
        )

    def retest_many(
        self,
        requests,
    ) -> list[RetestResult]:
        return self.retest_service.retest_many(
            requests
        )


__all__ = [
    "ValidationService",
]
