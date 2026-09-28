"""Build security scan reports for SecureForge."""

from __future__ import annotations

from typing import Any

from secureforge.core.scan.models import SecurityScanResult


def build_scan_report(
    result: SecurityScanResult,
) -> dict[str, Any]:
    """Convert a security scan result into a report dictionary."""
    execution = result.execution

    findings = [
        _finding_to_dict(finding)
        for finding in result.findings
    ]

    report: dict[str, Any] = {
        "scan": {
            "scan_id": execution.scan_id,
            "application": execution.application,
            "version": execution.version,
            "commit_sha": execution.commit_sha,
            "profile": execution.profile,
            "environment": execution.environment,
            "started_at": execution.started_at,
            "completed_at": execution.completed_at,
            "status": str(execution.status),
        },
        "tools": [
            _tool_to_dict(tool)
            for tool in execution.tools
        ],
        "tool_errors": list(
            execution.tool_errors
        ),
        "findings": findings,
        "summary": _summary_to_dict(
            result
        ),
        "metadata": dict(
            result.metadata
        ),
    }

    if result.policy_evaluation is not None:
        report["policy_evaluation"] = _to_dict(
            result.policy_evaluation
        )

    if result.release_decision is not None:
        report["release_decision"] = _to_dict(
            result.release_decision
        )

    if result.risk_assessments:
        report["risk_assessments"] = [
            _to_dict(
                assessment
            )
            for assessment in result.risk_assessments
        ]

    if result.regression_failures:
        report["regression_failures"] = list(
            result.regression_failures
        )

    if result.errors:
        report["errors"] = list(
            result.errors
        )

    if result.warnings:
        report["warnings"] = list(
            result.warnings
        )

    return report


def _finding_to_dict(
    finding: Any,
) -> dict[str, Any]:
    """Convert a finding model into a serializable dictionary."""
    return _to_dict(
        finding
    )


def _tool_to_dict(
    tool: Any,
) -> dict[str, Any]:
    """Convert a tool execution result into a dictionary."""
    return _to_dict(
        tool
    )


def _summary_to_dict(
    result: SecurityScanResult,
) -> dict[str, Any]:
    """Build a compact finding summary."""
    findings = result.findings

    severity_counts: dict[str, int] = {}

    for finding in findings:
        severity = getattr(
            finding,
            "severity",
            "unknown",
        )

        if hasattr(
            severity,
            "value",
        ):
            severity = severity.value

        key = str(
            severity
        ).lower()

        severity_counts[key] = (
            severity_counts.get(
                key,
                0,
            )
            + 1
        )

    return {
        "total_findings": len(
            findings
        ),
        "severity_counts": severity_counts,
        "risk_assessments": len(
            result.risk_assessments
        ),
        "tool_errors": len(
            result.execution.tool_errors
        ),
        "errors": len(
            result.errors
        ),
        "warnings": len(
            result.warnings
        ),
    }


def _to_dict(
    value: Any,
) -> dict[str, Any] | Any:
    """Convert common SecureForge models to dictionaries."""
    if value is None:
        return None

    if isinstance(
        value,
        dict,
    ):
        return value

    if hasattr(
        value,
        "model_dump",
    ):
        return value.model_dump(
            mode="json"
        )

    if hasattr(
        value,
        "to_dict",
    ):
        return value.to_dict()

    if hasattr(
        value,
        "__dict__",
    ):
        return dict(
            value.__dict__
        )

    return value
