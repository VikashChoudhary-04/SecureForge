"""Integration helpers between validation and SecureForge findings."""

from __future__ import annotations

from dataclasses import dataclass

from secureforge.core.findings.models import (
    Finding,
    FindingStatus,
    ValidationStatus,
)

from .assessment import ValidationAssessment, assess_validation
from .models import ValidationOutcome, ValidationResult


@dataclass(frozen=True)
class FindingValidationUpdate:
    """Result of applying validation to a finding."""

    finding_id: str
    assessment: ValidationAssessment
    finding: Finding

    @property
    def confirmed(self) -> bool:
        return self.assessment.confirmed

    @property
    def remediated(self) -> bool:
        return self.assessment.remediation_verified

    @property
    def reopened(self) -> bool:
        return self.assessment.confirmed


def apply_validation_result(
    finding: Finding,
    result: ValidationResult,
) -> FindingValidationUpdate:
    """Apply validation without changing an open finding to a closed state."""
    if finding.finding_id != result.finding_id:
        raise ValueError(
            "Finding ID does not match validation result: "
            f"{finding.finding_id} != {result.finding_id}"
        )

    assessment = assess_validation(result)

    if assessment.confirmed:
        finding.validation_status = ValidationStatus.VALIDATED
        finding.status = FindingStatus.OPEN
        finding.last_seen = finding.last_seen

    elif assessment.remediation_verified:
        finding.mark_remediated()
        finding.mark_verified()

    elif result.outcome == ValidationOutcome.REJECTED:
        finding.validation_status = ValidationStatus.VALIDATED
        finding.status = FindingStatus.OPEN

    return FindingValidationUpdate(
        finding_id=finding.finding_id,
        assessment=assessment,
        finding=finding,
    )


def apply_validation_results(
    findings: list[Finding],
    results: list[ValidationResult],
) -> list[FindingValidationUpdate]:
    """Apply validation results to matching findings."""
    findings_by_id = {
        finding.finding_id: finding
        for finding in findings
    }

    updates: list[FindingValidationUpdate] = []

    for result in results:
        finding = findings_by_id.get(
            result.finding_id
        )

        if finding is None:
            raise ValueError(
                "Validation result references unknown finding: "
                f"{result.finding_id}"
            )

        updates.append(
            apply_validation_result(
                finding,
                result,
            )
        )

    return updates


__all__ = [
    "FindingValidationUpdate",
    "apply_validation_result",
    "apply_validation_results",
]
