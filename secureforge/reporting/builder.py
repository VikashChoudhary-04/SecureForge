"""Build complete SecureForge security reports."""

from __future__ import annotations

from datetime import datetime, timezone

from secureforge.core.findings.models import Finding
from secureforge.core.policy.models import PolicyDecision
from secureforge.core.release_gate.models import ReleaseGateDecision
from secureforge.core.risk.models import RiskAssessment
from secureforge.regression import (
    RegressionGateDecision,
    RegressionSuiteResult,
    )

from .models import (
    DecisionReport,
    PolicyReport,
    RegressionGateReport,
    RegressionReport,
    ReleaseMetadata,
    RemediationReport,
    ReportFinding,
    RiskReport,
    ScanMetadata,
    SecurityReport,
    )
from .regression import build_regression_report
from .regression_gate import build_regression_gate_report

class SecurityReportBuilder:
    """Convert SecureForge domain results into a security report."""
    
    def build(
        self,
        *,
        release: ReleaseMetadata,
        scan: ScanMetadata,
        findings: list[Finding],
        risk: RiskAssessment,
        policy: PolicyDecision,
        decision: ReleaseGateDecision,
        remediation: RemediationReport | None = None,
        regression: RegressionSuiteResult | None = None,
        regression_gate: RegressionGateDecision | None = None,
        generated_at: str | None = None,
    ) -> SecurityReport:
        """Build a complete security report."""
        report_findings = [
            self._build_finding(
                finding
            )
            for finding in findings
        ]
    
        regression_report = (
            build_regression_report(
                regression
            )
            if regression is not None
            else RegressionReport(
                suite_id="not-run",
                suite_name="Regression Testing",
                status="skipped",
                total=0,
                passed=0,
                failed=0,
                errors=0,
                skipped=0,
                tests=[],
                started_at=None,
                completed_at=None,
                duration_seconds=0.0,
            )
        )
    
        regression_gate_report = (
            build_regression_gate_report(
                regression_gate
            )
            if regression_gate is not None
            else None
        )
    
        return SecurityReport(
            release=release,
            scan=scan,
            findings=report_findings,
            risk=self._build_risk(
                risk
            ),
            policy=self._build_policy(
                policy
            ),
            remediation=(
                remediation
                if remediation is not None
                else RemediationReport(
                    total=0,
                    open=0,
                    in_progress=0,
                    resolved=0,
                    verified=0,
                    items=[],
                )
            ),
            regression=regression_report,
            regression_gate=regression_gate_report,
            decision=self._build_decision(
                decision
            ),
            generated_at=(
                generated_at
                if generated_at is not None
                else datetime.now(
                    timezone.utc
                ).isoformat()
            ),
        )

@staticmethod
def _build_finding(
    finding: Finding,
) -> ReportFinding:
    """Convert a domain finding into a report finding."""
    return ReportFinding(
        finding_id=finding.finding_id,
        title=finding.title,
        source=finding.source,
        asset=finding.asset,
        application=finding.application,
        endpoint=finding.endpoint,
        parameter=finding.parameter,
        severity=finding.severity.value,
        confidence=finding.confidence.value,
        status=finding.status.value,
        validation_status=(
            finding.validation_status.value
        ),
        cwe=finding.cwe,
        owasp_mapping=finding.owasp_mapping,
        security_requirement=(
            finding.security_requirement
        ),
        description=finding.description,
        impact=finding.impact,
        remediation=finding.remediation,
        evidence=[
            evidence.model_dump()
            for evidence in finding.evidence
        ],
        correlations=list(
            finding.correlations
        ),
        regression_test=(
            finding.regression_test
        ),
    )

@staticmethod
def _build_risk(
    risk: RiskAssessment,
) -> RiskReport:
    """Convert a risk assessment into a report risk section."""
    return RiskReport(
        score=risk.score,
        highest_severity=(
            risk.highest_severity.value
        ),
        confirmed_critical=(
            risk.confirmed_critical
        ),
        confirmed_high=(
            risk.confirmed_high
        ),
        factors=[
            factor.model_dump()
            if hasattr(
                factor,
                "model_dump",
            )
            else factor
            for factor in risk.factors
        ],
    )

@staticmethod
def _build_policy(
    policy: PolicyDecision,
) -> PolicyReport:
    """Convert a policy decision into a report policy section."""
    return PolicyReport(
        policy_name=policy.policy_name,
        actions=[
            action.model_dump()
            if hasattr(
                action,
                "model_dump",
            )
            else action
            for action in policy.actions
        ],
        tool_errors=list(
            policy.tool_errors
        ),
        regression_failures=list(
            policy.regression_failures
        ),
        exceptions=[
            exception.model_dump()
            if hasattr(
                exception,
                "model_dump",
            )
            else exception
            for exception in policy.exceptions
        ],
    )

@staticmethod
def _build_decision(
    decision: ReleaseGateDecision,
) -> DecisionReport:
    """Convert a release-gate decision into a report decision."""
    return DecisionReport(
        status=decision.status.value,
        reason=decision.reason,
        release_allowed=decision.release_allowed,
    )
