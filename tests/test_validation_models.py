"""Tests for SecureForge validation models."""

from secureforge.validation.models import (
    RetestResult,
    ValidationEvidence,
    ValidationMethod,
    ValidationOutcome,
    ValidationRequest,
    ValidationResult,
    ValidationSummary,
)


def test_validation_evidence_accepts_supported_fields() -> None:
    evidence = ValidationEvidence(
        method=ValidationMethod.HTTP,
        description="Controlled HTTP validation.",
        request="GET /vulnerable/search?q=test",
        response="HTTP/1.1 200 OK",
        expected="Input should be safely handled.",
        observed="Unexpected reflected input.",
    )

    assert evidence.method == ValidationMethod.HTTP
    assert evidence.request == "GET /vulnerable/search?q=test"
    assert evidence.observed == "Unexpected reflected input."


def test_validation_result_status_properties() -> None:
    confirmed = ValidationResult(
        finding_id="SQLI-001",
        outcome=ValidationOutcome.CONFIRMED,
        message="SQL injection reproduced.",
        validator="http",
        validated_at="2026-09-27T12:00:00+00:00",
    )

    rejected = ValidationResult(
        finding_id="SQLI-001",
        outcome=ValidationOutcome.REJECTED,
        message="SQL injection no longer reproduced.",
        validator="http",
        validated_at="2026-09-27T12:00:00+00:00",
    )

    inconclusive = ValidationResult(
        finding_id="SQLI-001",
        outcome=ValidationOutcome.INCONCLUSIVE,
        message="Response requires manual interpretation.",
        validator="http",
        validated_at="2026-09-27T12:00:00+00:00",
    )

    error = ValidationResult(
        finding_id="SQLI-001",
        outcome=ValidationOutcome.ERROR,
        message="Validator failed.",
        validator="http",
        validated_at="2026-09-27T12:00:00+00:00",
    )

    assert confirmed.confirmed is True
    assert confirmed.rejected is False
    assert confirmed.inconclusive is False
    assert confirmed.failed is False

    assert rejected.rejected is True
    assert inconclusive.inconclusive is True
    assert error.failed is True


def test_validation_request_defaults_are_safe() -> None:
    request = ValidationRequest(
        finding_id="BOLA-001",
        target="http://localhost:5000",
    )

    assert request.method == ValidationMethod.HTTP
    assert request.validator == "secureforge"
    assert request.metadata == {}


def test_retest_result_detects_fixed_finding() -> None:
    validation = ValidationResult(
        finding_id="XSS-001",
        outcome=ValidationOutcome.REJECTED,
        message="Payload no longer reproduced.",
        validator="http",
        validated_at="2026-09-27T12:00:00+00:00",
        remediation_verified=True,
    )

    result = RetestResult(
        finding_id="XSS-001",
        previous_outcome=ValidationOutcome.CONFIRMED,
        current_outcome=ValidationOutcome.REJECTED,
        remediation_verified=True,
        message="Finding fixed.",
        validation=validation,
    )

    assert result.fixed is True
    assert result.regression_required is False


def test_retest_result_requires_regression_when_still_confirmed() -> None:
    validation = ValidationResult(
        finding_id="BOLA-001",
        outcome=ValidationOutcome.CONFIRMED,
        message="BOLA remains reproducible.",
        validator="api",
        validated_at="2026-09-27T12:00:00+00:00",
    )

    result = RetestResult(
        finding_id="BOLA-001",
        previous_outcome=ValidationOutcome.CONFIRMED,
        current_outcome=ValidationOutcome.CONFIRMED,
        remediation_verified=False,
        message="Finding remains open.",
        validation=validation,
    )

    assert result.fixed is False
    assert result.regression_required is True


def test_validation_summary_counts_results() -> None:
    results = [
        ValidationResult(
            finding_id="SQLI-001",
            outcome=ValidationOutcome.CONFIRMED,
            message="Confirmed.",
            validator="http",
            validated_at="2026-09-27T12:00:00+00:00",
        ),
        ValidationResult(
            finding_id="XSS-001",
            outcome=ValidationOutcome.REJECTED,
            message="Rejected.",
            validator="http",
            validated_at="2026-09-27T12:01:00+00:00",
            remediation_verified=True,
        ),
        ValidationResult(
            finding_id="BOLA-001",
            outcome=ValidationOutcome.INCONCLUSIVE,
            message="Inconclusive.",
            validator="api",
            validated_at="2026-09-27T12:02:00+00:00",
        ),
        ValidationResult(
            finding_id="SECRET-001",
            outcome=ValidationOutcome.ERROR,
            message="Validator error.",
            validator="command",
            validated_at="2026-09-27T12:03:00+00:00",
        ),
    ]

    summary = ValidationSummary(
        total=4,
        confirmed=1,
        rejected=1,
        inconclusive=1,
        errors=1,
        remediated=1,
        results=results,
    )

    assert summary.total == 4
    assert summary.confirmed == 1
    assert summary.rejected == 1
    assert summary.inconclusive == 1
    assert summary.errors == 1
    assert summary.remediated == 1
    assert summary.all_validated is False
