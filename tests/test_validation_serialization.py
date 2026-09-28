```python id="q4m8s1"
"""Tests for SecureForge validation serialization."""

import json

from secureforge.validation.assessment import assess_validation
from secureforge.validation.gate import evaluate_validation_run
from secureforge.validation.models import (
    RetestResult,
    ValidationOutcome,
    ValidationResult,
    ValidationSummary,
)
from secureforge.validation.runner import ValidationRun
from secureforge.validation.serialization import (
    assessment_to_dict,
    dumps_retest_result,
    dumps_validation_result,
    dumps_validation_summary,
    gate_decision_to_dict,
    retest_result_to_dict,
    validation_result_to_dict,
    validation_summary_to_dict,
)


def build_result(
    finding_id: str = "SQLI-001",
    *,
    outcome: ValidationOutcome = ValidationOutcome.CONFIRMED,
    remediation_verified: bool = False,
) -> ValidationResult:
    return ValidationResult(
        finding_id=finding_id,
        outcome=outcome,
        message="Validation completed.",
        validator="test",
        validated_at="2026-09-28T09:00:00+05:30",
        remediation_verified=remediation_verified,
    )


def test_validation_result_to_dict_is_json_compatible() -> None:
    result = build_result()

    serialized = validation_result_to_dict(result)

    assert serialized["finding_id"] == "SQLI-001"
    assert serialized["outcome"] == "confirmed"
    assert serialized["validator"] == "test"
    assert serialized["remediation_verified"] is False


def test_validation_summary_to_dict_is_json_compatible() -> None:
    result = build_result()

    summary = ValidationSummary(
        total=1,
        confirmed=1,
        results=[result],
    )

    serialized = validation_summary_to_dict(summary)

    assert serialized["total"] == 1
    assert serialized["confirmed"] == 1
    assert len(serialized["results"]) == 1
    assert serialized["results"][0]["finding_id"] == "SQLI-001"


def test_retest_result_to_dict_is_json_compatible() -> None:
    validation = build_result(
        outcome=ValidationOutcome.REJECTED,
        remediation_verified=True,
    )

    result = RetestResult(
        finding_id="SQLI-001",
        previous_outcome=ValidationOutcome.CONFIRMED,
        current_outcome=ValidationOutcome.REJECTED,
        remediation_verified=True,
        message="Remediation verified.",
        validation=validation,
    )

    serialized = retest_result_to_dict(result)

    assert serialized["finding_id"] == "SQLI-001"
    assert serialized["previous_outcome"] == "confirmed"
    assert serialized["current_outcome"] == "rejected"
    assert serialized["remediation_verified"] is True
    assert serialized["validation"]["outcome"] == "rejected"


def test_assessment_to_dict_contains_derived_state() -> None:
    assessment = assess_validation(
        build_result()
    )

    serialized = assessment_to_dict(assessment)

    assert serialized["finding_id"] == "SQLI-001"
    assert serialized["outcome"] == "confirmed"
    assert serialized["confirmed"] is True
    assert serialized["regression_required"] is True
    assert serialized["resolved"] is False
    assert serialized["actionable"] is True


def test_gate_decision_to_dict_contains_all_decision_fields() -> None:
    result = build_result(
        outcome=ValidationOutcome.REJECTED,
        remediation_verified=True,
    )

    summary = ValidationSummary(
        total=1,
        rejected=1,
        remediated=1,
        results=[result],
    )

    decision = evaluate_validation_run(
        ValidationRun(summary=summary)
    )

    serialized = gate_decision_to_dict(decision)

    assert serialized["allowed"] is True
    assert serialized["blocked"] is False
    assert serialized["status"] == "passed"
    assert serialized["confirmed_findings"] == []
    assert serialized["unresolved_findings"] == []
    assert serialized["remediation_verified"] == ["SQLI-001"]
    assert serialized["requires_attention"] is False


def test_dumps_validation_result_produces_valid_json() -> None:
    result = build_result()

    payload = dumps_validation_result(result)

    decoded = json.loads(payload)

    assert decoded["finding_id"] == "SQLI-001"
    assert decoded["outcome"] == "confirmed"


def test_dumps_validation_summary_produces_valid_json() -> None:
    result = build_result()

    summary = ValidationSummary(
        total=1,
        confirmed=1,
        results=[result],
    )

    payload = dumps_validation_summary(summary)

    decoded = json.loads(payload)

    assert decoded["total"] == 1
    assert decoded["results"][0]["finding_id"] == "SQLI-001"


def test_dumps_retest_result_produces_valid_json() -> None:
    validation = build_result(
        outcome=ValidationOutcome.REJECTED,
        remediation_verified=True,
    )

    result = RetestResult(
        finding_id="SQLI-001",
        previous_outcome=ValidationOutcome.CONFIRMED,
        current_outcome=ValidationOutcome.REJECTED,
        remediation_verified=True,
        message="Remediation verified.",
        validation=validation,
    )

    payload = dumps_retest_result(result)

    decoded = json.loads(payload)

    assert decoded["finding_id"] == "SQLI-001"
    assert decoded["current_outcome"] == "rejected"
    assert decoded["fixed"] is True
```
