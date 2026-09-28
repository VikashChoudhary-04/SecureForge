```python
"""Build reporting models from SecureForge scan results."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from secureforge.core.scan.models import SecurityScanResult
from secureforge.validation.serialization import (
    assessment_to_dict,
    gate_decision_to_dict,
    retest_result_to_dict,
    validation_result_to_dict,
    validation_summary_to_dict,
)

from .models import (
    DecisionReport,
    RegressionGateReport,
    RegressionReport,
    RegressionTestReport,
    RemediationReport,
    ReportFinding,
    RiskReport,
    ScanMetadata,
    SecurityReport,
)


def build_scan_report(
    result: SecurityScanResult,
) -> SecurityReport:
    """Build a complete security report from a scan result."""
    pipeline = result.pipeline
    execution = result.execution

    findings = [
        _build_finding_report(finding)
        for finding in pipeline.findings
    ]

    validation_report = None

    if pipeline.validation is not None:
        validation_report = validation_summary_to_dict(
            pipeline.validation
        )

    validation_gate_report = None

    if pipeline.validation_gate is not None:
        validation_gate_report = gate_decision_to_dict(
            pipeline.validation_gate
        )

    validation_results = []

    if pipeline.validation_results is not None:
        validation_results = [
            validation_result_to_dict(item)
            for item in pipeline.validation_results
        ]

    regression_report = _build_regression_report(
        pipeline.regression
    )

    regression_gate_report = _build_regression_gate_report(
        pipeline.regression_gate
    )

    return SecurityReport(
        release=_build_release_metadata(
            result
        ),
        scan=ScanMetadata(
            scan_id=execution.scan_id,
            profile=execution.profile,
            application=execution.application,
            version=execution.version,
            commit_sha=execution.commit_sha,
            environment=execution.environment,
            started_at=execution.started_at,
            completed_at=execution.completed_at,
            tools=execution.tools,
            tool_errors=execution.tool_errors,
        ),
        findings=findings,
        risk=_build_risk_report(
            pipeline.risk
        ),
        policy=_build_policy_report(
            pipeline.policy
        ),
        decision=DecisionReport(
            allowed=pipeline.release_allowed,
            blocked=pipeline.release_blocked,
            status=pipeline.release_gate.status,
            reason=pipeline.release_gate.reason,
        ),
        remediation=_build_remediation_report(
            findings
        ),
        regression=regression_report,
        regression_gate=regression_gate_report,
        validation=validation_report,
        validation_results=validation_results,
        validation_gate=validation_gate_report,
        generated_at=datetime.now(
            timezone.utc
        ).isoformat(),
    )


def _build_release_metadata(
    result: SecurityScanResult,
) -> dict[str, Any]:
    """Build release metadata for the report."""
    execution = result.execution

    return {
        "scan_id": execution.scan_id,
        "application": execution.application,
        "version": execution.version,
        "commit_sha": execution.commit_sha,
        "environment": execution.environment,
        "release_allowed": result.pipeline.release_allowed,
        "release_blocked": result.pipeline.release_blocked,
    }


def _build_finding_report(
    finding,
) -> ReportFinding:
    """Convert a core finding into a report finding."""
    return ReportFinding(
        finding_id=finding.finding_id,
        title=finding.title,
        source=finding.source,
        asset=finding.asset,
        application=finding.application,
        endpoint=finding.endpoint,
        parameter=finding.parameter,
        cwe=finding.cwe,
        owasp_mapping=finding.owasp_mapping,
        security_requirement=finding.security_requirement,
        severity=finding.severity.value,
        confidence=finding.confidence.value,
        evidence=[
            evidence.model_dump(mode="json")
            for evidence in finding.evidence
        ],
        description=finding.description,
        impact=finding.impact,
        remediation=finding.remediation,
        status=finding.status.value,
        validation_status=finding.validation_status.value,
        first_seen=finding.first_seen,
        last_seen=finding.last_seen,
        regression_test=finding.regression_test,
        correlation_ids=list(
            finding.correlation_ids
        ),
    )


def _build_risk_report(
    risk,
) -> RiskReport:
    """Convert the risk assessment into a report model."""
    return RiskReport(
        overall_score=risk.overall_score,
        overall_severity=risk.overall_severity.value,
        blocked=risk.blocked,
        factors=[
            factor.model_dump(mode="json")
            for factor in risk.factors
        ],
        evaluated_at=risk.evaluated_at,
    )


def _build_policy_report(
    policy,
) -> dict[str, Any]:
    """Convert the policy decision into report data."""
    return {
        "allowed": policy.allowed,
        "status": policy.status,
        "reason": policy.reason,
        "actions": [
            action.model_dump(mode="json")
            for action in policy.actions
        ],
        "exceptions": [
            exception.model_dump(mode="json")
            for exception in policy.exceptions
        ],
    }


def _build_remediation_report(
    findings: list[ReportFinding],
) -> RemediationReport:
    """Build remediation information from reported findings."""
    open_findings = [
        finding
        for finding in findings
        if finding.status not in {
            "remediated",
            "verified",
        }
    ]

    remediated_findings = [
        finding
        for finding in findings
        if finding.status in {
            "remediated",
            "verified",
        }
    ]

    return RemediationReport(
        total=len(findings),
        open_count=len(open_findings),
        remediated_count=len(remediated_findings),
        findings=[
            {
                "finding_id": finding.finding_id,
                "title": finding.title,
                "status": finding.status,
                "remediation": finding.remediation,
            }
            for finding in findings
            if finding.remediation
        ],
    )


def _build_regression_report(
    regression,
) -> RegressionReport | None:
    """Build regression reporting data."""
    if regression is None:
        return None

    tests = []

    for item in regression.tests:
        if isinstance(item, RegressionTestReport):
            tests.append(item)
            continue

        if hasattr(item, "model_dump"):
            data = item.model_dump(mode="json")
        elif isinstance(item, dict):
            data = item
        else:
            data = {
                "test_id": getattr(
                    item,
                    "test_id",
                    "unknown",
                ),
                "status": getattr(
                    item,
                    "status",
                    "unknown",
                ),
                "message": getattr(
                    item,
                    "message",
                    "",
                ),
            }

        tests.append(
            RegressionTestReport(
                test_id=data.get(
                    "test_id",
                    "unknown",
                ),
                status=data.get(
                    "status",
                    "unknown",
                ),
                message=data.get(
                    "message",
                    "",
                ),
            )
        )

    return RegressionReport(
        total=regression.total,
        passed=regression.passed,
        failed=regression.failed,
        errored=regression.errored,
        skipped=regression.skipped,
        tests=tests,
    )


def _build_regression_gate_report(
    decision,
) -> RegressionGateReport | None:
    """Build regression-gate reporting data."""
    if decision is None:
        return None

    return RegressionGateReport(
        allowed=decision.allowed,
        blocked=decision.blocked,
        status=decision.status,
        reason=decision.reason,
        failed_tests=list(
            decision.failed_tests
        ),
        errored_tests=list(
            decision.errored_tests
        ),
        skipped_tests=list(
            decision.skipped_tests
        ),
        failures=list(
            decision.failures
        ),
    )


__all__ = [
    "build_scan_report",
]
```
