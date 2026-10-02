"""Build complete SecureForge security reports."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from secureforge.core.findings import Finding, FindingStatus, ValidationStatus
from secureforge.core.policy import PolicyDecision
from secureforge.core.release_gate import ReleaseGateDecision
from secureforge.core.risk import RiskAssessment
from secureforge.regression import RegressionGateDecision, RegressionSuiteResult
from secureforge.validation.models import ValidationResult, ValidationSummary

from .models import (
    DecisionReport,
    PolicyReport,
    RegressionGateReport,
    RegressionReport,
    ReleaseMetadata,
    RemediationItem,
    RemediationReport,
    ReportFinding,
    RiskReport,
    ScanMetadata,
    SecurityReport,
    ValidationGateReport,
    ValidationReport,
)
from .regression import build_regression_report


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _duration(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


class SecurityReportBuilder:
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
        validation: ValidationSummary | None = None,
        validation_results: list[ValidationResult] | None = None,
        validation_gate: Any | None = None,
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
        findings = list(findings or [])
        decision = decision or release_gate

        if decision is None:
            decision = ReleaseGateDecision(
                status="review",
                reason="No release-gate decision supplied.",
                release_allowed=False,
            )

        if release is None:
            release = ReleaseMetadata(
                release_id=release_id or "",
                scan_id=scan_id or "",
                application=application or "SecureCommerce",
                version=version or "0.1.0",
                environment=environment or "lab",
                release_allowed=bool(decision.release_allowed),
                release_blocked=not bool(decision.release_allowed),
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

        if remediation is None:
            remediation = RemediationReport(
                total=len(findings),
                open=sum(f.status == FindingStatus.OPEN for f in findings),
                remediated=sum(
                    f.status == FindingStatus.REMEDIATED for f in findings
                ),
                verified=sum(
                    f.validation_status == ValidationStatus.VERIFIED
                    for f in findings
                ),
                items=[
                    RemediationItem(
                        finding_id=f.finding_id,
                        title=f.title,
                        status=f.status.value,
                        remediation=f.remediation,
                    )
                    for f in findings
                ],
            )

        regression_report = (
            build_regression_report(regression)
            if regression is not None
            else RegressionReport(
                suite_id="not-run",
                suite_name="Regression Testing",
                status="skipped",
            )
        )

        gate_report = (
            RegressionGateReport(
                allowed=regression_gate.allowed,
                blocked=not regression_gate.allowed,
                status=str(regression_gate.status),
                reason=regression_gate.reason,
                failed_tests=list(regression_gate.failed_tests),
                errored_tests=list(regression_gate.errored_tests),
                skipped_tests=list(regression_gate.skipped_tests),
                failures=list(regression_gate.failures),
            )
            if regression_gate is not None
            else None
        )

        validation_report = self._build_validation(
            validation, validation_results
        )
        validation_gate_report = self._build_validation_gate(validation_gate)

        return SecurityReport(
            release=release,
            scan=scan,
            findings=[self._build_finding(f) for f in findings],
            risk=self._build_risk(risk),
            policy=self._build_policy(policy),
            remediation=remediation,
            decision=self._build_decision(decision),
            regression=regression_report,
            regression_gate=gate_report,
            validation=validation_report,
            validation_results=(
                validation_report.results if validation_report else []
            ),
            validation_gate=validation_gate_report,
            generated_at=(
                generated_at or datetime.now(timezone.utc).isoformat()
            ),
        )

    @staticmethod
    def _build_finding(finding):
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
            evidence=[e.model_dump(mode="json") for e in finding.evidence],
            regression_test=finding.regression_test,
            correlation_ids=list(finding.correlation_ids),
        )

    @staticmethod
    def _build_risk(risk):
        highest = risk.highest_severity or risk.contextual_risk
        return RiskReport(
            score=risk.score if risk.score is not None else risk.risk_score,
            highest_severity=getattr(highest, "value", str(highest)),
            finding_count=risk.finding_count or 0,
            confirmed_critical=risk.confirmed_critical,
            confirmed_high=risk.confirmed_high,
            factors=(
                dict(risk.factors)
                if isinstance(risk.factors, dict)
                else list(risk.factors)
            ),
            evaluated_at=_stringify(risk.evaluated_at),
        )

    @staticmethod
    def _build_policy(policy):
        action = getattr(policy, "action", "")
        action = getattr(action, "value", action)
        return PolicyReport(
            policy_name=getattr(policy, "policy_name", "default"),
            action=action,
            allowed=bool(getattr(policy, "allowed", False)),
            reason=getattr(policy, "reason", ""),
            violations=list(getattr(policy, "violations", [])),
            actions=getattr(policy, "actions", {}),
            tool_errors=list(getattr(policy, "tool_errors", [])),
            regression_failures=list(
                getattr(policy, "regression_failures", [])
            ),
            exceptions=getattr(policy, "exceptions", []),
        )

    @staticmethod
    def _build_decision(decision):
        status = getattr(decision, "status", "review")
        status = getattr(status, "value", status)
        if status == "blocked":
            status = "block"
        return DecisionReport(
            status=status,
            reason=getattr(decision, "reason", ""),
            release_allowed=bool(
                getattr(decision, "release_allowed", False)
            ),
        )

    @staticmethod
    def _build_validation(validation, validation_results):
        if validation is None and validation_results is None:
            return None
        if validation is None:
            results = list(validation_results or [])
            validation = ValidationSummary(
                total=len(results),
                confirmed=sum(r.confirmed for r in results),
                rejected=sum(r.rejected for r in results),
                inconclusive=sum(r.inconclusive for r in results),
                errors=sum(r.failed for r in results),
                remediated=sum(r.remediation_verified for r in results),
                results=results,
            )
        from .models import ValidationResultReport, ValidationReport
        reports = [
            ValidationResultReport(
                finding_id=r.finding_id,
                outcome=getattr(r.outcome, "value", r.outcome),
                message=r.message,
                validator=r.validator,
                validated_at=_stringify(r.validated_at),
                remediation_verified=r.remediation_verified,
                confirmed=r.confirmed,
                rejected=r.rejected,
                inconclusive=r.inconclusive,
                failed=r.failed,
                evidence=[
                    e.model_dump(mode="json")
                    for e in r.evidence
                ],
            )
            for r in validation.results
        ]
        return ValidationReport(
            total=validation.total,
            confirmed=validation.confirmed,
            rejected=validation.rejected,
            inconclusive=validation.inconclusive,
            errors=validation.errors,
            remediated=validation.remediated,
            all_validated=validation.all_validated,
            results=reports,
        )

    @staticmethod
    def _build_validation_gate(gate):
        if gate is None:
            return None
        return ValidationGateReport(
            allowed=bool(getattr(gate, "allowed", False)),
            blocked=bool(getattr(gate, "blocked", False)),
            status=str(getattr(gate, "status", "")),
            reason=str(getattr(gate, "reason", "")),
            confirmed_findings=list(getattr(gate, "confirmed_findings", ())),
            unresolved_findings=list(getattr(gate, "unresolved_findings", ())),
            remediation_verified=list(getattr(gate, "remediation_verified", ())),
            inconclusive_findings=list(
                getattr(gate, "inconclusive_findings", ())
            ),
            errored_findings=list(getattr(gate, "errored_findings", ())),
            requires_attention=bool(
                getattr(gate, "requires_attention", False)
            ),
        )


__all__ = ["SecurityReportBuilder"]
