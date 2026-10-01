"""Build complete SecureForge security reports."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

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
    ValidationGateReport,
    ValidationReport,
    ValidationResultReport,
)


class SecurityReportBuilder:
    """Convert SecureForge domain results into a security report."""

    def build(
        self,
        *,
        release: ReleaseMetadata | None = None,
        scan: ScanMetadata | None = None,
        findings: list[Finding] | None = None,
        risk: RiskAssessment,
        policy: PolicyDecision,
        decision: ReleaseGateDecision | None = None,
        remediation: RemediationReport | None = None,
        regression: RegressionSuiteResult | None = None,
        regression_gate: RegressionGateDecision | None = None,
        generated_at: str | None = None,
        release_id: str | None = None,
        application: str | None = None,
        version: str | None = None,
        environment: str | None = None,
        profile: str | None = None,
        scan_id: str | None = None,
        scan_status: str | None = None,
        integrations: list[str] | None = None,
        release_gate: ReleaseGateDecision | None = None,
        **_: Any,
    ) -> SecurityReport:
        """Build a report using either modern or legacy arguments."""
        findings = list(findings or [])

        decision = decision or release_gate

        if release is None:
            release = ReleaseMetadata(
                release_id=release_id or "",
                scan_id=scan_id or "",
                application=application or "SecureCommerce",
                version=version or "0.1.0",
                environment=environment or "lab",
                release_allowed=(
                    bool(decision.release_allowed)
                    if decision is not None
                    else False
                ),
                release_blocked=(
                    not bool(decision.release_allowed)
                    if decision is not None
                    else True
                ),
            )

        if scan is None:
            scan = ScanMetadata(
                scan_id=scan_id or release.scan_id or "",
                profile=profile or "standard",
                application=application or release.application,
                version=version or release.version,
                target="",
                environment=environment or release.environment,
                started_at="",
                completed_at="",
                status=scan_status or "completed",
                integrations=integrations or [],
            )

        report_findings = [
            self._build_finding(finding)
            for finding in findings
        ]

        regression_report = (
            self._build_regression(regression)
            if regression is not None
            else RegressionReport(
                suite_id="not-run",
                suite_name="Regression Testing",
                status="skipped",
            )
        )

        regression_gate_report = (
            self._build_regression_gate(regression_gate)
            if regression_gate is not None
            else None
        )

        decision = decision or ReleaseGateDecision(
            status="review",
            reason="No release-gate decision supplied.",
            release_allowed=False,
        )

        return SecurityReport(
            release=release,
            scan=scan,
            findings=report_findings,
            risk=self._build_risk(risk),
            policy=self._build_policy(policy),
            remediation=(
                remediation
                if remediation is not None
                else RemediationReport(
                    total=0,
                    items=[],
                )
            ),
            regression=regression_report,
            regression_gate=regression_gate_report,
            decision=self._build_decision(decision),
            generated_at=(
                generated_at
                or datetime.now(timezone.utc).isoformat()
            ),
        )

    @staticmethod
    def _build_finding(finding: Finding) -> ReportFinding:
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
            validation_status=finding.validation_status.value,
            cwe=finding.cwe,
            owasp_mapping=finding.owasp_mapping,
            security_requirement=finding.security_requirement,
            description=finding.description,
            impact=finding.impact,
            remediation=finding.remediation,
            evidence=[
                evidence.model_dump()
                for evidence in finding.evidence
            ],
            correlations=list(finding.correlations),
            regression_test=finding.regression_test,
        )

    @staticmethod
    def _build_risk(risk: RiskAssessment) -> RiskReport:
        factors = risk.factors
        if isinstance(factors, dict):
            factor_data: Any = dict(factors)
        else:
            factor_data = [
                (
                    factor.model_dump()
                    if hasattr(factor, "model_dump")
                    else factor
                )
                for factor in factors
            ]

        highest = risk.highest_severity or risk.contextual_risk
        highest_value = getattr(highest, "value", str(highest))

        return RiskReport(
            score=(
                risk.score
                if risk.score is not None
                else risk.risk_score
            ),
            highest_severity=highest_value,
            finding_count=risk.finding_count or 0,
            confirmed_critical=risk.confirmed_critical,
            confirmed_high=risk.confirmed_high,
            factors=factor_data,
            evaluated_at=risk.evaluated_at,
        )

    @staticmethod
    def _build_policy(policy: PolicyDecision) -> PolicyReport:
        actions = getattr(policy, "actions", [])
        return PolicyReport(
            policy_name=getattr(policy, "policy_name", "default"),
            action=getattr(policy, "action", ""),
            allowed=bool(getattr(policy, "allowed", False)),
            reason=getattr(policy, "reason", ""),
            violations=list(getattr(policy, "violations", [])),
            actions=(
                actions.model_dump()
                if hasattr(actions, "model_dump")
                else actions
            ),
            tool_errors=list(getattr(policy, "tool_errors", [])),
            regression_failures=list(
                getattr(policy, "regression_failures", [])
            ),
            exceptions=getattr(policy, "exceptions", []),
        )

    @staticmethod
    def _build_decision(
        decision: ReleaseGateDecision,
    ) -> DecisionReport:
        status = getattr(decision, "status", "review")
        status = getattr(status, "value", status)
        return DecisionReport(
            status=status,
            reason=getattr(decision, "reason", ""),
            release_allowed=bool(
                getattr(decision, "release_allowed", False)
            ),
        )

    @staticmethod
    def _build_regression(
        regression: RegressionSuiteResult,
    ) -> RegressionReport:
        results = getattr(regression, "results", [])
        tests = [
            {
                "test_id": item.test_id,
                "status": getattr(item.status, "value", item.status),
                "message": item.message,
            }
            for item in results
        ]

        return RegressionReport(
            suite_id=regression.suite_id,
            suite_name=getattr(regression, "suite_name", ""),
            status=getattr(
                regression.status,
                "value",
                regression.status,
            ),
            total=regression.total,
            passed=regression.passed,
            failed=regression.failed,
            errors=regression.errors,
            skipped=regression.skipped,
            tests=tests,
            started_at=regression.started_at,
            completed_at=regression.completed_at,
            duration_seconds=regression.duration_seconds,
            tests_total=regression.total,
            tests_failed=regression.failed,
        )

    @staticmethod
    def _build_regression_gate(
        gate: RegressionGateDecision,
    ) -> RegressionGateReport:
        failed = list(gate.failed_tests)
        errored = list(gate.errored_tests)
        skipped = list(gate.skipped_tests)
        return RegressionGateReport(
            allowed=gate.allowed,
            blocked=not gate.allowed,
            status=gate.status,
            reason=gate.reason,
            failed_tests=failed,
            errored_tests=errored,
            skipped_tests=skipped,
            failures=failed + errored,
        )


__all__ = ["SecurityReportBuilder"]
