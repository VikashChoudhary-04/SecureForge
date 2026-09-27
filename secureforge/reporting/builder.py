"""Build complete SecureForge security reports from domain results."""

from **future** import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from secureforge.core.findings import Finding
from secureforge.core.policy import PolicyDecision
from secureforge.core.release_gate import ReleaseGateDecision
from secureforge.core.risk import RiskAssessment

from .models import (
DecisionReport,
PolicyReport,
RegressionReport,
RegressionTestReport,
ReleaseMetadata,
RemediationReport,
ReportFinding,
RiskReport,
ScanMetadata,
SecurityReport,
)

def utc_now() -> datetime:
"""Return the current UTC timestamp."""
return datetime.now(timezone.utc)

class SecurityReportBuilder:
"""Build a report from normalized SecureForge security results."""

```
def build(
    self,
    *,
    release_id: str,
    application: str,
    version: str,
    environment: str,
    profile: str,
    scan_id: str,
    scan_status: str,
    integrations: Iterable[str],
    findings: Iterable[Finding],
    risk: RiskAssessment,
    policy: PolicyDecision,
    release_gate: ReleaseGateDecision,
    commit_sha: str | None = None,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
    regression_results: Iterable[dict[str, Any]] | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurityReport:
    """Build a complete security report."""
    finding_list = list(findings)
    regression_list = list(
        regression_results or []
    )

    report_findings = [
        self._build_finding(finding)
        for finding in finding_list
    ]

    regression = self._build_regression_report(
        regression_list
    )

    remediation = self._build_remediation_report(
        finding_list
    )

    release = ReleaseMetadata(
        release_id=release_id,
        application=application,
        version=version,
        commit_sha=commit_sha,
        environment=environment,
        profile=profile,
    )

    scan = ScanMetadata(
        scan_id=scan_id,
        status=scan_status,
        started_at=started_at,
        completed_at=completed_at,
        integrations=list(integrations),
    )

    risk_report = self._build_risk_report(risk)

    policy_report = self._build_policy_report(policy)

    decision = self._build_decision_report(
        release_gate
    )

    return SecurityReport(
        release=release,
        scan=scan,
        findings=report_findings,
        risk=risk_report,
        policy=policy_report,
        remediation=remediation,
        regression=regression,
        decision=decision,
        generated_at=utc_now(),
        metadata=dict(metadata or {}),
    )

@staticmethod
def _build_finding(
    finding: Finding,
) -> ReportFinding:
    """Convert a domain finding into report data."""
    return ReportFinding(
        finding_id=finding.finding_id,
        title=finding.title,
        source=finding.source,
        source_finding_ids=(
            [finding.source_finding_id]
            if finding.source_finding_id
            else []
        ),
        application=finding.application,
        asset=finding.asset,
        endpoint=finding.endpoint,
        parameter=finding.parameter,
        cwe=finding.cwe,
        owasp=finding.owasp,
        security_requirement=(
            finding.security_requirement
        ),
        severity=finding.severity.value,
        confidence=finding.confidence.value,
        description=finding.description,
        impact=finding.impact,
        remediation=finding.remediation,
        status=finding.status.value,
        validation_status=(
            finding.validation_status.value
        ),
        regression_test=finding.regression_test,
        evidence_count=len(finding.evidence),
    )

@staticmethod
def _build_risk_report(
    risk: RiskAssessment,
) -> RiskReport:
    """Convert a risk assessment into report data."""
    return RiskReport(
        overall_score=risk.score,
        highest_severity=risk.highest_severity,
        confirmed_critical=risk.confirmed_critical,
        confirmed_high=risk.confirmed_high,
        risk_factors=dict(
            risk.factors
        ),
    )

@staticmethod
def _build_policy_report(
    policy: PolicyDecision,
) -> PolicyReport:
    """Convert a policy decision into report data."""
    return PolicyReport(
        policy_name=policy.policy_name,
        critical_action=policy.actions.get(
            "critical",
            "block",
        ),
        high_action=policy.actions.get(
            "high",
            "block",
        ),
        medium_action=policy.actions.get(
            "medium",
            "review",
        ),
        low_action=policy.actions.get(
            "low",
            "pass",
        ),
        info_action=policy.actions.get(
            "info",
            "pass",
        ),
        tool_errors=list(
            policy.tool_errors
        ),
        regression_failures=list(
            policy.regression_failures
        ),
        exceptions=[
            dict(exception)
            for exception in policy.exceptions
        ],
    )

@staticmethod
def _build_decision_report(
    release_gate: ReleaseGateDecision,
) -> DecisionReport:
    """Convert a release-gate decision into report data."""
    return DecisionReport(
        status=release_gate.status.value,
        reason=release_gate.reason,
        release_allowed=release_gate.release_allowed,
    )

@staticmethod
def _build_remediation_report(
    findings: list[Finding],
) -> RemediationReport:
    """Summarize finding remediation state."""
    open_findings = sum(
        finding.status.value
        in {
            "open",
            "in_progress",
            "reopened",
        }
        for finding in findings
    )

    remediated_findings = sum(
        finding.status.value == "remediated"
        for finding in findings
    )

    verified_findings = sum(
        finding.status.value == "verified"
        for finding in findings
    )

    pending_retests = sum(
        finding.status.value
        in {
            "remediated",
            "reopened",
        }
        for finding in findings
    )

    return RemediationReport(
        open_findings=open_findings,
        remediated_findings=remediated_findings,
        verified_findings=verified_findings,
        pending_retests=pending_retests,
    )

@staticmethod
def _build_regression_report(
    results: list[dict[str, Any]],
) -> RegressionReport:
    """Build the regression-test summary."""
    tests = [
        RegressionTestReport(
            test_id=str(
                result.get(
                    "test_id",
                    "unknown",
                )
            ),
            requirement=str(
                result.get(
                    "requirement",
                    "",
                )
            ),
            status=str(
                result.get(
                    "status",
                    "unknown",
                )
            ),
            expected_result=result.get(
                "expected_result"
            ),
            actual_result=result.get(
                "actual_result"
            ),
            message=result.get(
                "message"
            ),
        )
        for result in results
    ]

    passed = sum(
        test.status.lower()
        in {
            "passed",
            "pass",
            "success",
        }
        for test in tests
    )

    failed = sum(
        test.status.lower()
        in {
            "failed",
            "fail",
            "error",
        }
        for test in tests
    )

    return RegressionReport(
        suite=(
            "SecureCommerce Security "
            "Regression Suite"
        ),
        tests_total=len(tests),
        tests_passed=passed,
        tests_failed=failed,
        tests=tests,
    )
```
