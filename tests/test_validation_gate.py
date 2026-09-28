```python
"""Tests for the SecureForge validation gate."""

from secureforge.validation.gate import (
    ValidationGateDecision,
    evaluate_retest_run,
    evaluate_validation_run,
)
from secureforge.validation.models import (
    RetestResult,
    ValidationOutcome,
    ValidationResult,
    ValidationSummary,
)
from secureforge.validation.runner import (
    RetestRun,
    ValidationRun,
)


def build_validation_result(
    finding_id: str,
    outcome: ValidationOutcome,
    *,
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


def build_validation_run(
    results: list[ValidationResult],
) -> ValidationRun:
    summary = ValidationSummary(
        total=len(results),
        confirmed=sum(
            result.outcome == ValidationOutcome.CONFIRMED
            for result in results
        ),
        rejected=sum(
            result.outcome == ValidationOutcome.REJECTED
            for result in results
        ),
        inconclusive=sum(
            result.outcome == ValidationOutcome.INCONCLUSIVE
            for result in results
        ),
        errors=sum(
            result.outcome == ValidationOutcome.ERROR
            for result in results
        ),
        remediated=sum(
            result.remediation_verified
            for result in results
        ),
        results=results,
    )

    return ValidationRun(summary=summary)


def build_retest_result(
    finding_id: str,
    outcome: ValidationOutcome,
    *,
    remediation_verified: bool = False,
) -> RetestResult:
    validation = build_validation_result(
        finding_id,
        outcome,
        remediation_verified=remediation_verified,
    )

    return RetestResult(
        finding_id=finding_id,
        previous_outcome=ValidationOutcome.CONFIRMED,
        current_outcome=outcome,
        remediation_verified=remediation_verified,
        message="Retest result.",
        validation=validation,
    )


def test_validation_gate_blocks_confirmed_findings() -> None:
    run = build_validation_run(
        [
            build_validation_result(
                "SQLI-001",
                ValidationOutcome.CONFIRMED,
            ),
        ]
    )

    decision = evaluate_validation_run(run)

    assert isinstance(decision, ValidationGateDecision)
    assert decision.allowed is False
    assert decision.blocked is True
    assert decision.status == "blocked"
    assert decision.confirmed_findings == ("SQLI-001",)
    assert decision.unresolved_findings == ("SQLI-001",)
    assert decision.requires_attention is True


def test_validation_gate_passes_rejected_findings() -> None:
    run = build_validation_run(
        [
            build_validation_result(
                "SQLI-001",
                ValidationOutcome.REJECTED,
            ),
            build_validation_result(
                "XSS-001",
                ValidationOutcome.REJECTED,
                remediation_verified=True,
            ),
        ]
    )

    decision = evaluate_validation_run(run)

    assert decision.allowed is True
    assert decision.blocked is False
    assert decision.status == "passed"
    assert decision.confirmed_findings == ()
    assert decision.unresolved_findings == ()
    assert decision.remediation_verified == ("XSS-001",)
    assert decision.requires_attention is False


def test_validation_gate_requires_review_for_inconclusive() -> None:
    run = build_validation_run(
        [
            build_validation_result(
                "BOLA-001",
                ValidationOutcome.INCONCLUSIVE,
            ),
        ]
    )

    decision = evaluate_validation_run(run)

    assert decision.allowed is False
    assert decision.status == "review"
    assert decision.inconclusive_findings == ("BOLA-001",)
    assert decision.unresolved_findings == ("BOLA-001",)
    assert decision.requires_attention is True


def test_validation_gate_blocks_validation_errors() -> None:
    run = build_validation_run(
        [
            build_validation_result(
                "SECRET-001",
                ValidationOutcome.ERROR,
            ),
        ]
    )

    decision = evaluate_validation_run(run)

    assert decision.allowed is False
    assert decision.status == "error"
    assert decision.errored_findings == ("SECRET-001",)
    assert decision.unresolved_findings == ("SECRET-001",)
    assert decision.requires_attention is True


def test_validation_gate_confirmed_takes_precedence_over_error() -> None:
    run = build_validation_run(
        [
            build_validation_result(
                "SQLI-001",
                ValidationOutcome.CONFIRMED,
            ),
            build_validation_result(
                "SECRET-001",
                ValidationOutcome.ERROR,
            ),
        ]
    )

    decision = evaluate_validation_run(run)

    assert decision.status == "blocked"
    assert decision.allowed is False
    assert decision.confirmed_findings == ("SQLI-001",)
    assert decision.errored_findings == ("SECRET-001",)


def test_retest_gate_passes_verified_remediation() -> None:
    run = RetestRun(
        results=[
            build_retest_result(
                "SQLI-001",
                ValidationOutcome.REJECTED,
                remediation_verified=True,
            ),
            build_retest_result(
                "XSS-001",
                ValidationOutcome.REJECTED,
                remediation_verified=True,
            ),
        ]
    )

    decision = evaluate_retest_run(run)

    assert decision.allowed is True
    assert decision.status == "passed"
    assert decision.confirmed_findings == ()
    assert decision.unresolved_findings == ()
    assert decision.remediation_verified == (
        "SQLI-001",
        "XSS-001",
    )


def test_retest_gate_blocks_still_confirmed_findings() -> None:
    run = RetestRun(
        results=[
            build_retest_result(
                "BOLA-001",
                ValidationOutcome.CONFIRMED,
            ),
        ]
    )

    decision = evaluate_retest_run(run)

    assert decision.allowed is False
    assert decision.status == "blocked"
    assert decision.confirmed_findings == ("BOLA-001",)
    assert decision.unresolved_findings == ("BOLA-001",)


def test_retest_gate_requires_review_for_inconclusive() -> None:
    run = RetestRun(
        results=[
            build_retest_result(
                "XSS-001",
                ValidationOutcome.INCONCLUSIVE,
            ),
        ]
    )

    decision = evaluate_retest_run(run)

    assert decision.allowed is False
    assert decision.status == "review"
    assert decision.inconclusive_findings == ("XSS-001",)
    assert decision.unresolved_findings == ("XSS-001",)


def test_retest_gate_blocks_errors() -> None:
    run = RetestRun(
        results=[
            build_retest_result(
                "SECRET-001",
                ValidationOutcome.ERROR,
            ),
        ]
    )

    decision = evaluate_retest_run(run)

    assert decision.allowed is False
    assert decision.status == "error"
    assert decision.errored_findings == ("SECRET-001",)
    assert decision.unresolved_findings == ("SECRET-001",)


def test_retest_gate_confirmed_takes_precedence_over_error() -> None:
    run = RetestRun(
        results=[
            build_retest_result(
                "BOLA-001",
                ValidationOutcome.CONFIRMED,
            ),
            build_retest_result(
                "SECRET-001",
                ValidationOutcome.ERROR,
            ),
        ]
    )

    decision = evaluate_retest_run(run)

    assert decision.status == "blocked"
    assert decision.confirmed_findings == ("BOLA-001",)
    assert decision.errored_findings == ("SECRET-001",)
```
