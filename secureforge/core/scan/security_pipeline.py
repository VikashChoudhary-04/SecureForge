"""Security evaluation pipeline for SecureForge scan results."""

from **future** import annotations

from collections.abc import Iterable

from secureforge.core.config import ScanConfiguration
from secureforge.core.correlation import CorrelationEngine
from secureforge.core.policy import (
PolicyConfig,
PolicyEngine,
)
from secureforge.core.release_gate import (
ReleaseGateEngine,
ReleaseGateInput,
)
from secureforge.core.risk import (
RiskContext,
RiskEngine,
)

from .models import ScanRun

class SecurityPipeline:
"""Run correlation, risk, policy, and release evaluation."""

```
def __init__(
    self,
    *,
    correlation_engine: CorrelationEngine | None = None,
    risk_engine: RiskEngine | None = None,
    policy_engine: PolicyEngine | None = None,
    release_gate_engine: ReleaseGateEngine | None = None,
) -> None:
    self.correlation_engine = (
        correlation_engine
        or CorrelationEngine()
    )

    self.risk_engine = (
        risk_engine
        or RiskEngine()
    )

    self.policy_engine = (
        policy_engine
        or PolicyEngine()
    )

    self.release_gate_engine = (
        release_gate_engine
        or ReleaseGateEngine()
    )

def evaluate(
    self,
    scan: ScanRun,
    configuration: ScanConfiguration,
    policy: PolicyConfig,
    *,
    risk_context: RiskContext | None = None,
    failed_regressions: Iterable[str] | None = None,
) -> ScanRun:
    """Evaluate a completed scan through the security decision pipeline."""
    correlations = self.correlation_engine.correlate(
        scan.findings
    )

    scan.summary.correlated_group_count = len(
        correlations
    )

    assessments = self._assess_risk(
        scan,
        risk_context,
    )

    scan.add_risk_assessments(
        assessments
    )

    regression_failures = list(
        failed_regressions
        or scan.regression_failures
    )

    for regression_id in regression_failures:
        scan.add_regression_failure(
            regression_id
        )

    policy_evaluation = self.policy_engine.evaluate(
        scan.findings,
        assessments,
        policy,
        tool_errors=scan.tool_error_count,
        failed_regressions=regression_failures,
    )

    scan.policy_evaluation = policy_evaluation

    release_input = ReleaseGateInput(
        application=scan.application,
        version=scan.version,
        commit_sha=scan.commit_sha,
        policy_decision=policy_evaluation.decision,
        blocking_findings=(
            policy_evaluation.blocking_findings
        ),
        review_findings=(
            policy_evaluation.review_findings
        ),
        failed_regressions=regression_failures,
        tool_errors=[
            result.error
            or (
                f"Tool '{result.tool_name}' "
                "failed."
            )
            for result in scan.tool_results
            if result.failed
        ],
        exceptions_applied=(
            policy_evaluation.exceptions_applied
        ),
        metadata={
            "profile": scan.profile.value,
            "environment": scan.environment,
            "policy_id": policy.policy_id,
            "policy_version": policy.version,
        },
    )

    scan.release_decision = (
        self.release_gate_engine.evaluate(
            release_input
        )
    )

    return scan

def _assess_risk(
    self,
    scan: ScanRun,
    default_context: RiskContext | None,
):
    """Assess contextual risk for every scan finding."""
    assessments = []

    for finding in scan.findings:
        context = self._context_for_finding(
            finding,
            scan,
            default_context,
        )

        assessments.append(
            self.risk_engine.evaluate(
                finding,
                context,
            )
        )

    return assessments

@staticmethod
def _context_for_finding(
    finding,
    scan: ScanRun,
    default_context: RiskContext | None,
) -> RiskContext:
    """Build a risk context for an individual finding."""
    if default_context is None:
        return RiskContext(
            environment=scan.environment,
            security_requirement=(
                finding.security_requirement
            ),
        )

    context = default_context.model_copy(
        deep=True
    )

    if context.security_requirement is None:
        context.security_requirement = (
            finding.security_requirement
        )

    return context
```
