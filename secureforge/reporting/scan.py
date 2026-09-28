```python
"""Build reporting models from SecureForge scan results."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from secureforge.core.scan.models import SecurityScanResult
from secureforge.validation.serialization import (
    gate_decision_to_dict,
    validation_result_to_dict,
    validation_summary_to_dict,
)

from .models import (
    DecisionReport,
    PolicyReport,
    RegressionGateReport,
    RegressionReport,
    RegressionTestReport,
    ReleaseMetadata,
    RemediationReport,
    ReportFinding,
    RiskReport,
    ScanMetadata,
    SecurityReport,
    ValidationGateReport,
    ValidationReport,
    ValidationResultReport,
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

    validation_report = _build_validation_report(
        pipeline.validation
    )

    validation_results = [
        ValidationResultReport(
            **validation_result_to_dict(item)
        )
        for item in (
            pipeline.validation_results
            if pipeline.validation_results is not None
            else []
        )
    ]

    validation_gate_report = _build_validation_gate_report(
        pipeline.validation_gate
    )

    return SecurityReport(
        release=ReleaseMetadata(
            scan_id=execution.scan_id,
            application=execution.application,
            version=execution.version,
            commit_sha=execution.commit_sha,
            environment=execution.environment,
            release_allowed=pipeline.release_allowed,
            release_blocked=pipeline.release_blocked,
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
        regression=_build_regression_report(
            pipeline.regression
        ),
        regression_gate=_build_regression_gate_report(
            pipeline.regression_gate
        ),
        validation=validation_report,
        validation_results=validation_results,
        validation_gate=validation_gate_report,
        generated_at=datetime.now(
            timezone.utc
        ).isoformat(),
    )


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
) -> PolicyReport:
    """Convert the policy decision into a report model."""
    return PolicyReport(
        allowed=policy.allowed,
        status=policy.status,
        reason=policy.reason,
        actions=[
            action.model_dump(mode="json")
            for action in policy.actions
        ],
        exceptions=[
            exception.model_dump(mode="json")
            for exception in policy.exceptions
        ],
    )


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


def _build_validation_report(
    summary,
) -> ValidationReport | None:
    """Build the validation summary report."""
    if summary is None:
        return None

    data = validation_summary_to_dict(summary)

    return ValidationReport(
        total=data["total"],
        confirmed=data["confirmed"],
        rejected=data["rejected"],
        inconclusive=data["inconclusive"],
        errors=data["errors"],
        remediated=data["remediated"],
        all_validated=data["all_validated"],
        results=[
            ValidationResultReport(**result)
            for result in data["results"]
        ],
    )


def _build_validation_gate_report(
    decision,
) -> ValidationGateReport | None:
    """Build the validation-gate report."""
    if decision is None:
        return None

    data = gate_decision_to_dict(decision)

    return ValidationGateReport(
        allowed=data["allowed"],
        blocked=data["blocked"],
        status=data["status"],
        reason=data["reason"],
        confirmed_findings=data["confirmed_findings"],
        unresolved_findings=data["unresolved_findings"],
        remediation_verified=data["remediation_verified"],
        inconclusive_findings=data["inconclusive_findings"],
        errored_findings=data["errored_findings"],
        requires_attention=data["requires_attention"],
    )


__all__ = [
    "build_scan_report",
]
```
