# Validation serialization helpers

from __future__ import annotations

import json
from typing import Any

from .assessment import ValidationAssessment
from .gate import ValidationGateDecision
from .models import (
    RetestResult,
    ValidationResult,
    ValidationSummary,
)


def validation_result_to_dict(
    result: ValidationResult,
) -> dict[str, Any]:
    """Convert a validation result into report-safe data."""
    data = result.model_dump(
        mode="json"
    )

    data["confirmed"] = result.confirmed
    data["rejected"] = result.rejected
    data["inconclusive"] = result.inconclusive
    data["failed"] = result.failed

    return data


def retest_result_to_dict(
    result: RetestResult,
) -> dict[str, Any]:
    """Convert a retest result into report-safe data."""
    data = result.model_dump(
        mode="json"
    )

    data["fixed"] = result.fixed
    data["regression_required"] = (
        result.regression_required
    )

    data["validation"] = (
        validation_result_to_dict(
            result.validation
        )
    )

    return data


def validation_summary_to_dict(
    summary: ValidationSummary,
) -> dict[str, Any]:
    """Convert a validation summary into report-safe data."""
    return {
        "total": summary.total,
        "confirmed": summary.confirmed,
        "rejected": summary.rejected,
        "inconclusive": summary.inconclusive,
        "errors": summary.errors,
        "remediated": summary.remediated,
        "all_validated": summary.all_validated,
        "results": [
            validation_result_to_dict(
                result
            )
            for result in summary.results
        ],
    }


def assessment_to_dict(
    assessment: ValidationAssessment,
) -> dict[str, Any]:
    """Convert a validation assessment into report-safe data."""
    return {
        "finding_id": assessment.finding_id,
        "outcome": assessment.outcome.value,
        "confirmed": assessment.confirmed,
        "rejected": assessment.rejected,
        "inconclusive": assessment.inconclusive,
        "errored": assessment.errored,
        "remediation_verified": (
            assessment.remediation_verified
        ),
        "regression_required": (
            assessment.regression_required
        ),
        "status": assessment.status,
        "reason": assessment.reason,
        "resolved": assessment.resolved,
        "actionable": assessment.actionable,
    }


def gate_decision_to_dict(
    decision: ValidationGateDecision,
) -> dict[str, Any]:
    """Convert a validation-gate decision into report-safe data."""
    return {
        "allowed": decision.allowed,
        "blocked": decision.blocked,
        "status": decision.status,
        "reason": decision.reason,
        "confirmed_findings": list(
            decision.confirmed_findings
        ),
        "unresolved_findings": list(
            decision.unresolved_findings
        ),
        "remediation_verified": list(
            decision.remediation_verified
        ),
        "inconclusive_findings": list(
            decision.inconclusive_findings
        ),
        "errored_findings": list(
            decision.errored_findings
        ),
        "requires_attention": (
            decision.requires_attention
        ),
    }


def validation_results_to_dict(
    results: list[ValidationResult],
) -> list[dict[str, Any]]:
    """Convert multiple validation results."""
    return [
        validation_result_to_dict(result)
        for result in results
    ]


def retest_results_to_dict(
    results: list[RetestResult],
) -> list[dict[str, Any]]:
    """Convert multiple retest results."""
    return [
        retest_result_to_dict(result)
        for result in results
    ]


def assessments_to_dict(
    assessments: list[ValidationAssessment],
) -> list[dict[str, Any]]:
    """Convert multiple validation assessments."""
    return [
        assessment_to_dict(assessment)
        for assessment in assessments
    ]


def dumps_validation_result(
    result: ValidationResult,
) -> str:
    """Serialize one validation result to JSON."""
    return json.dumps(
        validation_result_to_dict(result),
        indent=2,
        sort_keys=True,
    )


def dumps_validation_summary(
    summary: ValidationSummary,
) -> str:
    """Serialize a validation summary to JSON."""
    return json.dumps(
        validation_summary_to_dict(summary),
        indent=2,
        sort_keys=True,
    )


__all__ = [
    "assessment_to_dict",
    "assessments_to_dict",
    "dumps_validation_result",
    "dumps_validation_summary",
    "gate_decision_to_dict",
    "retest_result_to_dict",
    "retest_results_to_dict",
    "validation_result_to_dict",
    "validation_results_to_dict",
    "validation_summary_to_dict",
]
