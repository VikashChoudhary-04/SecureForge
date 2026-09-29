"""Tests for the SecureForge validation engine."""

from secureforge.validation.base import BaseValidator, ValidationError
from secureforge.validation.engine import ValidationEngine
from secureforge.validation.models import (
    ValidationMethod,
    ValidationOutcome,
    ValidationRequest,
    ValidationResult,
)
from secureforge.validation.registry import ValidatorRegistry


class SuccessfulValidator(BaseValidator):
    """Test validator that returns a confirmed result."""

    name = "successful"

    def supports(self, request: ValidationRequest) -> bool:
        return request.method == ValidationMethod.MANUAL

    def validate(self, request: ValidationRequest) -> ValidationResult:
        return ValidationResult(
            finding_id=request.finding_id,
            outcome=ValidationOutcome.CONFIRMED,
            message="Test validation succeeded.",
            validator=self.name,
            validated_at="2026-09-27T12:00:00+00:00",
        )


class FailingValidator(BaseValidator):
    """Test validator that raises a controlled validation error."""

    name = "failing"

    def supports(self, request: ValidationRequest) -> bool:
        return request.method == ValidationMethod.MANUAL

    def validate(self, request: ValidationRequest) -> ValidationResult:
        raise ValidationError("Controlled validation failure.")


class UnexpectedValidator(BaseValidator):
    """Test validator that raises an unexpected exception."""

    name = "unexpected"

    def supports(self, request: ValidationRequest) -> bool:
        return request.method == ValidationMethod.MANUAL

    def validate(self, request: ValidationRequest) -> ValidationResult:
        raise RuntimeError("Unexpected validator failure.")


def build_request(
    *,
    validator: str = "secureforge",
) -> ValidationRequest:
    return ValidationRequest(
        finding_id="TEST-001",
        target="http://localhost:5000",
        method=ValidationMethod.MANUAL,
        validator=validator,
    )


def test_engine_resolves_validator_by_request_method() -> None:
    registry = ValidatorRegistry()
    validator = SuccessfulValidator()
    registry.register(validator)

    engine = ValidationEngine(registry)

    result = engine.validate(build_request())

    assert result.outcome == ValidationOutcome.CONFIRMED
    assert result.validator == "successful"


def test_engine_resolves_explicit_validator_name() -> None:
    registry = ValidatorRegistry()
    registry.register(SuccessfulValidator())

    engine = ValidationEngine(registry)

    result = engine.validate(
        build_request(validator="successful")
    )

    assert result.outcome == ValidationOutcome.CONFIRMED
    assert result.validator == "successful"


def test_engine_converts_validation_error_to_error_result() -> None:
    registry = ValidatorRegistry()
    registry.register(FailingValidator())

    engine = ValidationEngine(registry)

    result = engine.validate(build_request())

    assert result.outcome == ValidationOutcome.ERROR
    assert result.validator == "failing"
    assert "Controlled validation failure." in result.message
    assert len(result.evidence) == 1


def test_engine_converts_unexpected_error_to_error_result() -> None:
    registry = ValidatorRegistry()
    registry.register(UnexpectedValidator())

    engine = ValidationEngine(registry)

    result = engine.validate(build_request())

    assert result.outcome == ValidationOutcome.ERROR
    assert result.validator == "unexpected"
    assert "Unexpected validation error" in result.message
    assert "RuntimeError" in result.message


def test_engine_validates_many_requests_in_order() -> None:
    registry = ValidatorRegistry()
    registry.register(SuccessfulValidator())

    engine = ValidationEngine(registry)

    requests = [
        ValidationRequest(
            finding_id="TEST-001",
            target="http://localhost:5000",
            method=ValidationMethod.MANUAL,
        ),
        ValidationRequest(
            finding_id="TEST-002",
            target="http://localhost:5000",
            method=ValidationMethod.MANUAL,
        ),
    ]

    results = engine.validate_many(requests)

    assert [result.finding_id for result in results] == [
        "TEST-001",
        "TEST-002",
    ]


def test_engine_describe_returns_registered_validators() -> None:
    registry = ValidatorRegistry()
    registry.register(SuccessfulValidator())

    engine = ValidationEngine(registry)

    description = engine.describe()

    assert description == [{"name": "successful"}]


def test_engine_reports_supported_methods() -> None:
    registry = ValidatorRegistry()
    registry.register(SuccessfulValidator())

    engine = ValidationEngine(registry)

    assert engine.supports_method(
        ValidationMethod.MANUAL
    ) is True

    assert engine.supports_method(
        ValidationMethod.HTTP
    ) is False
