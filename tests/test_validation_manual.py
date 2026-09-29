"""Tests for the SecureForge manual validator."""

import pytest

from secureforge.validation.base import ValidationError
from secureforge.validation.manual import ManualValidator
from secureforge.validation.models import (
    ValidationMethod,
    ValidationOutcome,
    ValidationRequest,
)


def build_request(
    **metadata: str,
) -> ValidationRequest:
    return ValidationRequest(
        finding_id="MANUAL-001",
        target="http://localhost:5000",
        method=ValidationMethod.MANUAL,
        metadata=metadata,
    )


def test_manual_validator_supports_manual_method() -> None:
    validator = ManualValidator()

    request = build_request(
        outcome="confirmed",
        message="Finding reproduced manually.",
    )

    assert validator.supports(request) is True


def test_manual_validator_rejects_other_methods() -> None:
    validator = ManualValidator()

    request = ValidationRequest(
        finding_id="MANUAL-001",
        target="http://localhost:5000",
        method=ValidationMethod.HTTP,
    )

    assert validator.supports(request) is False


def test_manual_validator_requires_outcome() -> None:
    validator = ManualValidator()

    request = build_request(
        message="Finding reproduced manually.",
    )

    with pytest.raises(
        ValidationError,
        match="requires an outcome",
    ):
        validator.validate(request)


def test_manual_validator_rejects_invalid_outcome() -> None:
    validator = ManualValidator()

    request = build_request(
        outcome="unknown",
        message="Finding reproduced manually.",
    )

    with pytest.raises(
        ValidationError,
        match="Invalid manual validation outcome",
    ):
        validator.validate(request)


def test_manual_validator_requires_message() -> None:
    validator = ManualValidator()

    request = build_request(
        outcome="confirmed",
    )

    with pytest.raises(
        ValidationError,
        match="requires a message",
    ):
        validator.validate(request)


def test_manual_validator_creates_confirmed_result() -> None:
    validator = ManualValidator()

    request = build_request(
        outcome="confirmed",
        message="BOLA reproduced using a second user account.",
        description="Manual authorization test.",
        request="GET /api/users/2",
        response="HTTP/1.1 200 OK",
        expected="HTTP 403 Forbidden.",
        observed="HTTP 200 OK.",
    )

    result = validator.validate(request)

    assert result.finding_id == "MANUAL-001"
    assert result.outcome == ValidationOutcome.CONFIRMED
    assert result.message == (
        "BOLA reproduced using a second user account."
    )
    assert result.validator == "manual"
    assert result.evidence[0].description == (
        "Manual authorization test."
    )
    assert result.evidence[0].request == (
        "GET /api/users/2"
    )
    assert result.evidence[0].response == (
        "HTTP/1.1 200 OK"
    )
    assert result.evidence[0].expected == (
        "HTTP 403 Forbidden."
    )
    assert result.evidence[0].observed == (
        "HTTP 200 OK."
    )


def test_manual_validator_supports_rejected_result() -> None:
    validator = ManualValidator()

    request = build_request(
        outcome="rejected",
        message="SQL injection could not be reproduced.",
    )

    result = validator.validate(request)

    assert result.outcome == ValidationOutcome.REJECTED
    assert result.rejected is True


def test_manual_validator_supports_inconclusive_result() -> None:
    validator = ManualValidator()

    request = build_request(
        outcome="inconclusive",
        message="Application behavior requires further analysis.",
    )

    result = validator.validate(request)

    assert result.outcome == ValidationOutcome.INCONCLUSIVE
    assert result.inconclusive is True


def test_manual_validator_supports_error_result() -> None:
    validator = ManualValidator()

    request = build_request(
        outcome="error",
        message="Manual validation could not be completed.",
    )

    result = validator.validate(request)

    assert result.outcome == ValidationOutcome.ERROR
    assert result.failed is True


def test_manual_validator_records_remediation_verification() -> None:
    validator = ManualValidator()

    request = build_request(
        outcome="rejected",
        message="Previously confirmed XSS is no longer reproducible.",
        remediation_verified="true",
    )

    result = validator.validate(request)

    assert result.remediation_verified is True


def test_manual_validator_defaults_remediation_to_false() -> None:
    validator = ManualValidator()

    request = build_request(
        outcome="confirmed",
        message="Finding remains reproducible.",
    )

    result = validator.validate(request)

    assert result.remediation_verified is False
