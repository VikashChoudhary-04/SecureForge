"""Tests for SecureForge remediation retesting."""

from secureforge.validation.engine import ValidationEngine
from secureforge.validation.models import (
    ValidationMethod,
    ValidationOutcome,
    ValidationRequest,
    ValidationResult,
)
from secureforge.validation.registry import ValidatorRegistry
from secureforge.validation.retest import RetestService
from secureforge.validation.service import ValidationService
from secureforge.validation.base import BaseValidator


class RetestValidator(BaseValidator):
    """Deterministic validator for retesting scenarios."""

    name = "retest-test"

    def supports(self, request: ValidationRequest) -> bool:
        return request.method == ValidationMethod.MANUAL

    def validate(self, request: ValidationRequest) -> ValidationResult:
        outcome = request.metadata.get(
            "current_outcome",
            "inconclusive",
        )

        return ValidationResult(
            finding_id=request.finding_id,
            outcome=ValidationOutcome(outcome),
            message=f"Current outcome: {outcome}.",
            validator=self.name,
            validated_at="2026-09-28T09:00:00+05:30",
        )


def build_service() -> RetestService:
    registry = ValidatorRegistry(
        validators=[RetestValidator()]
    )
    engine = ValidationEngine(registry)
    validation_service = ValidationService(engine)

    return RetestService(validation_service)


def build_request(
    finding_id: str,
    *,
    current_outcome: str,
) -> ValidationRequest:
    return ValidationRequest(
        finding_id=finding_id,
        target="http://localhost:5000",
        method=ValidationMethod.MANUAL,
        metadata={
            "current_outcome": current_outcome,
        },
    )


def test_retest_marks_confirmed_to_rejected_as_fixed() -> None:
    service = build_service()

    result = service.retest(
        request=build_request(
            "SQLI-001",
            current_outcome="rejected",
        ),
        previous_outcome=ValidationOutcome.CONFIRMED,
    )

    assert result.finding_id == "SQLI-001"
    assert result.previous_outcome == ValidationOutcome.CONFIRMED
    assert result.current_outcome == ValidationOutcome.REJECTED
    assert result.remediation_verified is True
    assert result.fixed is True
    assert result.regression_required is False
    assert "no longer reproducible" in result.message


def test_retest_keeps_confirmed_finding_open() -> None:
    service = build_service()

    result = service.retest(
        request=build_request(
            "BOLA-001",
            current_outcome="confirmed",
        ),
        previous_outcome=ValidationOutcome.CONFIRMED,
    )

    assert result.remediation_verified is False
    assert result.fixed is False
    assert result.regression_required is True
    assert "remains reproducible" in result.message


def test_retest_handles_inconclusive_result() -> None:
    service = build_service()

    result = service.retest(
        request=build_request(
            "XSS-001",
            current_outcome="inconclusive",
        ),
        previous_outcome=ValidationOutcome.CONFIRMED,
    )

    assert result.current_outcome == ValidationOutcome.INCONCLUSIVE
    assert result.remediation_verified is False
    assert result.fixed is False
    assert result.regression_required is False
    assert "inconclusive" in result.message


def test_retest_handles_validation_error() -> None:
    service = build_service()

    result = service.retest(
        request=build_request(
            "SECRET-001",
            current_outcome="error",
        ),
        previous_outcome=ValidationOutcome.CONFIRMED,
    )

    assert result.current_outcome == ValidationOutcome.ERROR
    assert result.remediation_verified is False
    assert result.fixed is False
    assert result.regression_required is False
    assert "error" in result.message


def test_retest_of_previous_rejected_finding_does_not_claim_remediation() -> None:
    service = build_service()

    result = service.retest(
        request=build_request(
            "XSS-001",
            current_outcome="rejected",
        ),
        previous_outcome=ValidationOutcome.REJECTED,
    )

    assert result.remediation_verified is False
    assert result.fixed is False
    assert result.current_outcome == ValidationOutcome.REJECTED


def test_retest_many_preserves_order() -> None:
    service = build_service()

    results = service.retest_many(
        [
            (
                build_request(
                    "SQLI-001",
                    current_outcome="rejected",
                ),
                ValidationOutcome.CONFIRMED,
            ),
            (
                build_request(
                    "BOLA-001",
                    current_outcome="confirmed",
                ),
                ValidationOutcome.CONFIRMED,
            ),
        ]
    )

    assert [result.finding_id for result in results] == [
        "SQLI-001",
        "BOLA-001",
    ]

    assert results[0].fixed is True
    assert results[1].regression_required is True
