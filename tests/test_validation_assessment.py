```python
"""Tests for SecureForge validation assessment."""

from secureforge.validation.assessment import (
    assess_many,
    assess_validation,
)
from secureforge.validation.models import (
    ValidationOutcome,
    ValidationResult,
)


def build_result(
    *,
    finding_id: str = "TEST-001",
    outcome: ValidationOutcome,
    remediation_verified: bool = False,
) -> ValidationResult:
    return ValidationResult(
        finding_id=finding_id,
        outcome=outcome,
        message="Test validation result.",
        validator="test",
        validated_at="2026-09-28T09:00:00+05:30",
        remediation_verified=remediation_verified,
    )


def test_assessment_identifies_confirmed_finding() -> None:
    assessment = assess_validation(
        build_result(
            outcome=ValidationOutcome.CONFIRMED,
        )
    )

    assert assessment.finding_id == "TEST-001"
    assert assessment.confirmed is True
    assert assessment.rejected is False
    assert assessment.inconclusive is False
    assert assessment.errored is False
    assert assessment.remediation_verified is False
    assert assessment.regression_required is True
    assert assessment.status == "confirmed"
    assert assessment.actionable is True
    assert assessment.resolved is False


def test_assessment_identifies_rejected_finding() -> None:
    assessment = assess_validation(
        build_result(
            outcome=ValidationOutcome.REJECTED,
        )
    )

    assert assessment.confirmed is False
    assert assessment.rejected is True
    assert assessment.remediation_verified is False
    assert assessment.regression_required is False
    assert assessment.status == "rejected"
    assert assessment.actionable is False
    assert assessment.resolved is False


def test_assessment_identifies_verified_remediation() -> None:
    assessment = assess_validation(
        build_result(
            outcome=ValidationOutcome.REJECTED,
            remediation_verified=True,
        )
    )

    assert assessment.rejected is True
    assert assessment.remediation_verified is True
    assert assessment.regression_required is False
    assert assessment.status == "remediated"
    assert assessment.actionable is False
    assert assessment.resolved is True


def test_assessment_does_not_mark_confirmed_result_as_remediated() -> None:
    assessment = assess_validation(
        build_result(
            outcome=ValidationOutcome.CONFIRMED,
            remediation_verified=True,
        )
    )

    assert assessment.confirmed is True
    assert assessment.remediation_verified is False
    assert assessment.status == "confirmed"
    assert assessment.regression_required is True


def test_assessment_identifies_inconclusive_result() -> None:
    assessment = assess_validation(
        build_result(
            outcome=ValidationOutcome.INCONCLUSIVE,
        )
    )

    assert assessment.inconclusive is True
    assert assessment.actionable is True
    assert assessment.resolved is False
    assert assessment.regression_required is False
    assert assessment.status == "inconclusive"


def test_assessment_identifies_error_result() -> None:
    assessment = assess_validation(
        build_result(
            outcome=ValidationOutcome.ERROR,
        )
    )

    assert assessment.errored is True
    assert assessment.actionable is True
    assert assessment.resolved is False
    assert assessment.regression_required is False
    assert assessment.status == "error"


def test_assess_many_preserves_order() -> None:
    results = [
        build_result(
            finding_id="SQLI-001",
            outcome=ValidationOutcome.CONFIRMED,
        ),
        build_result(
            finding_id="XSS-001",
            outcome=ValidationOutcome.REJECTED,
        ),
        build_result(
            finding_id="BOLA-001",
            outcome=ValidationOutcome.INCONCLUSIVE,
        ),
    ]

    assessments = assess_many(results)

    assert [
        assessment.finding_id
        for assessment in assessments
    ] == [
        "SQLI-001",
        "XSS-001",
        "BOLA-001",
    ]

    assert assessments[0].status == "confirmed"
    assert assessments[1].status == "rejected"
    assert assessments[2].status == "inconclusive"
```
