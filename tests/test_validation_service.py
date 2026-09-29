"""Tests for the SecureForge validation service."""

from secureforge.validation.base import BaseValidator
from secureforge.validation.engine import ValidationEngine
from secureforge.validation.models import (
    ValidationMethod,
    ValidationOutcome,
    ValidationRequest,
    ValidationResult,
)
from secureforge.validation.registry import ValidatorRegistry
from secureforge.validation.service import ValidationService


class TestValidator(BaseValidator):
    """Deterministic validator used by service tests."""

    name = "test"

    def supports(self, request: ValidationRequest) -> bool:
        return request.method == ValidationMethod.MANUAL

    def validate(self, request: ValidationRequest) -> ValidationResult:
        outcome = request.metadata.get(
            "outcome",
            "confirmed",
        )

        return ValidationResult(
            finding_id=request.finding_id,
            outcome=ValidationOutcome(outcome),
            message=f"Validation result: {outcome}.",
            validator=self.name,
            validated_at="2026-09-28T09:00:00+05:30",
            remediation_verified=(
                request.metadata.get(
                    "remediation_verified",
                    "false",
                )
                == "true"
            ),
        )


def build_service() -> ValidationService:
    registry = ValidatorRegistry(
        validators=[TestValidator()]
    )
    engine = ValidationEngine(registry)

    return ValidationService(engine)


def build_request(
    finding_id: str,
    *,
    outcome: str = "confirmed",
    remediation_verified: str = "false",
) -> ValidationRequest:
    return ValidationRequest(
        finding_id=finding_id,
        target="http://localhost:5000",
        method=ValidationMethod.MANUAL,
        metadata={
            "outcome": outcome,
            "remediation_verified": remediation_verified,
        },
    )


def test_service_validates_single_finding() -> None:
    service = build_service()

    result = service.validate(
        build_request("SQLI-001")
    )

    assert result.finding_id == "SQLI-001"
    assert result.outcome == ValidationOutcome.CONFIRMED
    assert result.validator == "test"


def test_service_validates_multiple_findings() -> None:
    service = build_service()

    summary = service.validate_many(
        [
            build_request(
                "SQLI-001",
                outcome="confirmed",
            ),
            build_request(
                "XSS-001",
                outcome="rejected",
            ),
            build_request(
                "BOLA-001",
                outcome="inconclusive",
            ),
        ]
    )

    assert summary.total == 3
    assert summary.confirmed == 1
    assert summary.rejected == 1
    assert summary.inconclusive == 1
    assert summary.errors == 0


def test_service_summarizes_empty_results() -> None:
    summary = ValidationService.summarize([])

    assert summary.total == 0
    assert summary.confirmed == 0
    assert summary.rejected == 0
    assert summary.inconclusive == 0
    assert summary.errors == 0
    assert summary.remediated == 0
    assert summary.results == []
    assert summary.all_validated is False


def test_service_summarizes_errors() -> None:
    results = [
        ValidationResult(
            finding_id="TEST-001",
            outcome=ValidationOutcome.ERROR,
            message="Validation failed.",
            validator="test",
            validated_at="2026-09-28T09:00:00+05:30",
        ),
    ]

    summary = ValidationService.summarize(results)

    assert summary.total == 1
    assert summary.errors == 1
    assert summary.all_validated is False


def test_service_counts_remediated_findings() -> None:
    results = [
        ValidationResult(
            finding_id="XSS-001",
            outcome=ValidationOutcome.REJECTED,
            message="XSS no longer reproduced.",
            validator="test",
            validated_at="2026-09-28T09:00:00+05:30",
            remediation_verified=True,
        ),
        ValidationResult(
            finding_id="SQLI-001",
            outcome=ValidationOutcome.CONFIRMED,
            message="SQL injection remains reproducible.",
            validator="test",
            validated_at="2026-09-28T09:00:00+05:30",
        ),
    ]

    summary = ValidationService.summarize(results)

    assert summary.total == 2
    assert summary.remediated == 1


def test_service_returns_remediation_candidates() -> None:
    results = [
        ValidationResult(
            finding_id="XSS-001",
            outcome=ValidationOutcome.REJECTED,
            message="Fixed.",
            validator="test",
            validated_at="2026-09-28T09:00:00+05:30",
            remediation_verified=True,
        ),
        ValidationResult(
            finding_id="SQLI-001",
            outcome=ValidationOutcome.CONFIRMED,
            message="Still present.",
            validator="test",
            validated_at="2026-09-28T09:00:00+05:30",
        ),
    ]

    candidates = ValidationService.remediation_candidates(
        results
    )

    assert [item.finding_id for item in candidates] == [
        "XSS-001"
    ]


def test_service_returns_regression_candidates() -> None:
    results = [
        ValidationResult(
            finding_id="SQLI-001",
            outcome=ValidationOutcome.CONFIRMED,
            message="Still present.",
            validator="test",
            validated_at="2026-09-28T09:00:00+05:30",
        ),
        ValidationResult(
            finding_id="XSS-001",
            outcome=ValidationOutcome.REJECTED,
            message="Fixed.",
            validator="test",
            validated_at="2026-09-28T09:00:00+05:30",
            remediation_verified=True,
        ),
    ]

    candidates = ValidationService.regression_candidates(
        results
    )

    assert [item.finding_id for item in candidates] == [
        "SQLI-001"
    ]


def test_service_preserves_validation_order() -> None:
    service = build_service()

    summary = service.validate_many(
        [
            build_request("FINDING-001"),
            build_request("FINDING-002"),
            build_request("FINDING-003"),
        ]
    )

    assert [
        result.finding_id
        for result in summary.results
    ] == [
        "FINDING-001",
        "FINDING-002",
        "FINDING-003",
    ]
