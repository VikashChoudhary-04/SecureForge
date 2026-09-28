```python
"""Tests for SecureForge validation and finding integration."""

from secureforge.core.findings.models import (
    Confidence,
    Finding,
    FindingStatus,
    Severity,
    ValidationStatus,
)
from secureforge.validation.integration import (
    apply_validation_result,
    apply_validation_results,
)
from secureforge.validation.models import (
    ValidationOutcome,
    ValidationResult,
)


def build_finding(
    finding_id: str = "SQLI-001",
) -> Finding:
    return Finding(
        finding_id=finding_id,
        title="SQL Injection",
        source="dast",
        asset="securecommerce",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="Controlled SQL injection finding.",
        impact="Database queries may be manipulated.",
        remediation="Use parameterized queries.",
    )


def build_result(
    finding_id: str = "SQLI-001",
    *,
    outcome: ValidationOutcome,
    remediation_verified: bool = False,
) -> ValidationResult:
    return ValidationResult(
        finding_id=finding_id,
        outcome=outcome,
        message="Validation result.",
        validator="test",
        validated_at="2026-09-28T09:00:00+05:30",
        remediation_verified=remediation_verified,
    )


def test_confirmed_validation_updates_finding() -> None:
    finding = build_finding()

    update = apply_validation_result(
        finding,
        build_result(
            outcome=ValidationOutcome.CONFIRMED,
        ),
    )

    assert update.finding_id == "SQLI-001"
    assert update.confirmed is True
    assert update.remediated is False
    assert update.reopened is True
    assert update.assessment.status == "confirmed"
    assert finding.validation_status == ValidationStatus.VALIDATED
    assert finding.status == FindingStatus.OPEN


def test_verified_remediation_updates_finding() -> None:
    finding = build_finding()

    update = apply_validation_result(
        finding,
        build_result(
            outcome=ValidationOutcome.REJECTED,
            remediation_verified=True,
        ),
    )

    assert update.confirmed is False
    assert update.remediated is True
    assert update.reopened is False
    assert update.assessment.status == "remediated"
    assert finding.validation_status == ValidationStatus.VERIFIED
    assert finding.status == FindingStatus.VERIFIED


def test_rejected_validation_marks_finding_validated() -> None:
    finding = build_finding()

    update = apply_validation_result(
        finding,
        build_result(
            outcome=ValidationOutcome.REJECTED,
        ),
    )

    assert update.confirmed is False
    assert update.remediated is False
    assert update.assessment.status == "rejected"
    assert finding.validation_status == ValidationStatus.VALIDATED
    assert finding.status == FindingStatus.OPEN


def test_inconclusive_validation_does_not_change_validation_state() -> None:
    finding = build_finding()

    update = apply_validation_result(
        finding,
        build_result(
            outcome=ValidationOutcome.INCONCLUSIVE,
        ),
    )

    assert update.assessment.status == "inconclusive"
    assert finding.validation_status == ValidationStatus.NOT_VALIDATED
    assert finding.status == FindingStatus.OPEN


def test_error_validation_does_not_change_finding_state() -> None:
    finding = build_finding()

    update = apply_validation_result(
        finding,
        build_result(
            outcome=ValidationOutcome.ERROR,
        ),
    )

    assert update.assessment.status == "error"
    assert finding.validation_status == ValidationStatus.NOT_VALIDATED
    assert finding.status == FindingStatus.OPEN


def test_validation_result_must_match_finding_id() -> None:
    finding = build_finding("SQLI-001")

    result = build_result(
        "XSS-001",
        outcome=ValidationOutcome.CONFIRMED,
    )

    try:
        apply_validation_result(
            finding,
            result,
        )
    except ValueError as exc:
        assert "does not match" in str(exc)
    else:
        raise AssertionError(
            "Expected ValueError for mismatched finding IDs."
        )


def test_apply_validation_results_matches_findings_by_id() -> None:
    findings = [
        build_finding("SQLI-001"),
        build_finding("XSS-001"),
    ]

    results = [
        build_result(
            "XSS-001",
            outcome=ValidationOutcome.CONFIRMED,
        ),
        build_result(
            "SQLI-001",
            outcome=ValidationOutcome.REJECTED,
            remediation_verified=True,
        ),
    ]

    updates = apply_validation_results(
        findings,
        results,
    )

    assert [update.finding_id for update in updates] == [
        "XSS-001",
        "SQLI-001",
    ]

    assert updates[0].confirmed is True
    assert updates[1].remediated is True


def test_unknown_finding_id_is_rejected() -> None:
    findings = [
        build_finding("SQLI-001"),
    ]

    results = [
        build_result(
            "UNKNOWN-001",
            outcome=ValidationOutcome.CONFIRMED,
        ),
    ]

    try:
        apply_validation_results(
            findings,
            results,
        )
    except ValueError as exc:
        assert "unknown finding" in str(exc)
    else:
        raise AssertionError(
            "Expected ValueError for unknown finding."
        )
```
