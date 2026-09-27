"""Policy evaluation engine for SecureForge."""

from **future** import annotations

from collections.abc import Iterable

from secureforge.core.findings import Finding
from secureforge.core.risk import RiskAssessment, RiskLevel

from .models import (
PolicyAction,
PolicyConfig,
PolicyDecision,
PolicyEvaluation,
PolicyRule,
)

class PolicyEngine:
"""Evaluate security findings against a configured policy."""

```
_decision_priority = {
    PolicyDecision.PASS: 0,
    PolicyDecision.REVIEW: 1,
    PolicyDecision.BLOCK: 2,
}

def evaluate(
    self,
    findings: Iterable[Finding],
    assessments: Iterable[RiskAssessment],
    policy: PolicyConfig,
    *,
    tool_errors: int = 0,
    failed_regressions: Iterable[str] | None = None,
) -> PolicyEvaluation:
    """Evaluate findings and contextual risk against policy."""
    finding_list = list(findings)
    assessment_list = list(assessments)
    regression_failures = list(failed_regressions or [])

    assessment_map = {
        assessment.finding_id: assessment
        for assessment in assessment_list
    }

    triggered_rules: list[str] = []
    blocking_findings: list[str] = []
    review_findings: list[str] = []
    passed_findings: list[str] = []
    exceptions_applied: list[str] = []
    reasons: list[str] = []

    final_decision = PolicyDecision.PASS

    for finding in finding_list:
        assessment = assessment_map.get(finding.finding_id)

        if assessment is None:
            reasons.append(
                f"No risk assessment was available for "
                f"{finding.finding_id}."
            )
            review_findings.append(finding.finding_id)
            final_decision = self._higher_decision(
                final_decision,
                PolicyDecision.REVIEW,
            )
            continue

        if self._exception_applies(finding, policy):
            exception_id = self._get_exception_id(finding, policy)

            if exception_id:
                exceptions_applied.append(exception_id)

            passed_findings.append(finding.finding_id)

            reasons.append(
                f"Policy exception applied to "
                f"{finding.finding_id}."
            )
            continue

        rule = self._match_rule(
            finding,
            assessment,
            policy.rules,
        )

        if rule is None:
            review_findings.append(finding.finding_id)

            reasons.append(
                f"No explicit policy rule matched "
                f"{finding.finding_id}; review required."
            )

            final_decision = self._higher_decision(
                final_decision,
                PolicyDecision.REVIEW,
            )
            continue

        triggered_rules.append(rule.rule_id)

        decision = self._action_to_decision(rule.action)

        if decision == PolicyDecision.BLOCK:
            blocking_findings.append(finding.finding_id)
            reasons.append(
                f"{finding.finding_id} triggered blocking rule "
                f"{rule.rule_id}."
            )

        elif decision == PolicyDecision.REVIEW:
            review_findings.append(finding.finding_id)
            reasons.append(
                f"{finding.finding_id} triggered review rule "
                f"{rule.rule_id}."
            )

        else:
            passed_findings.append(finding.finding_id)

        final_decision = self._higher_decision(
            final_decision,
            decision,
        )

    if regression_failures:
        if policy.fail_on_regression_failure:
            final_decision = self._higher_decision(
                final_decision,
                PolicyDecision.BLOCK,
            )

            reasons.append(
                "Security regression tests failed: "
                + ", ".join(regression_failures)
                + "."
            )

        else:
            final_decision = self._higher_decision(
                final_decision,
                PolicyDecision.REVIEW,
            )

            reasons.append(
                "Security regression tests failed and require review: "
                + ", ".join(regression_failures)
                + "."
            )

    if tool_errors > 0:
        if policy.fail_on_tool_error:
            final_decision = self._higher_decision(
                final_decision,
                PolicyDecision.BLOCK,
            )

            reasons.append(
                f"{tool_errors} security tool execution error(s) "
                "were encountered."
            )

        else:
            final_decision = self._higher_decision(
                final_decision,
                PolicyDecision.REVIEW,
            )

            reasons.append(
                f"{tool_errors} security tool execution error(s) "
                "require review."
            )

    if not reasons:
        reasons.append("No policy conditions were triggered.")

    return PolicyEvaluation(
        decision=final_decision,
        triggered_rules=self._unique(triggered_rules),
        blocking_findings=self._unique(blocking_findings),
        review_findings=self._unique(review_findings),
        passed_findings=self._unique(passed_findings),
        exceptions_applied=self._unique(exceptions_applied),
        reasons=reasons,
        policy_id=policy.policy_id,
        policy_version=policy.version,
    )

def _match_rule(
    self,
    finding: Finding,
    assessment: RiskAssessment,
    rules: list[PolicyRule],
) -> PolicyRule | None:
    """Return the highest-priority matching enabled rule."""
    matching_rules: list[PolicyRule] = []

    for rule in rules:
        if not rule.enabled:
            continue

        if self._rule_matches(finding, assessment, rule):
            matching_rules.append(rule)

    if not matching_rules:
        return None

    return max(
        matching_rules,
        key=lambda rule: self._rule_priority(rule.action),
    )

@staticmethod
def _rule_matches(
    finding: Finding,
    assessment: RiskAssessment,
    rule: PolicyRule,
) -> bool:
    """Determine whether a policy rule matches a finding."""
    if rule.severity is not None:
        if finding.severity.value != rule.severity.lower():
            return False

    if rule.risk_level is not None:
        if assessment.contextual_risk.value != rule.risk_level.lower():
            return False

    return True

@staticmethod
def _exception_applies(
    finding: Finding,
    policy: PolicyConfig,
) -> bool:
    """Determine whether an enabled exception applies."""
    for exception in policy.exceptions:
        if not exception.enabled:
            continue

        if exception.finding_id == finding.finding_id:
            return True

        if (
            exception.requirement_id
            and finding.security_requirement
            and exception.requirement_id
            == finding.security_requirement
        ):
            return True

    return False

@staticmethod
def _get_exception_id(
    finding: Finding,
    policy: PolicyConfig,
) -> str | None:
    """Return the ID of the matching exception."""
    for exception in policy.exceptions:
        if not exception.enabled:
            continue

        if exception.finding_id == finding.finding_id:
            return exception.exception_id

        if (
            exception.requirement_id
            and finding.security_requirement
            and exception.requirement_id
            == finding.security_requirement
        ):
            return exception.exception_id

    return None

@staticmethod
def _action_to_decision(
    action: PolicyAction,
) -> PolicyDecision:
    """Convert a policy action into a policy decision."""
    return PolicyDecision(action.value)

def _higher_decision(
    self,
    current: PolicyDecision,
    candidate: PolicyDecision,
) -> PolicyDecision:
    """Return the higher-priority policy decision."""
    if (
        self._decision_priority[candidate]
        > self._decision_priority[current]
    ):
        return candidate

    return current

@staticmethod
def _rule_priority(action: PolicyAction) -> int:
    """Return the priority of a policy action."""
    priority = {
        PolicyAction.PASS: 0,
        PolicyAction.REVIEW: 1,
        PolicyAction.BLOCK: 2,
    }

    return priority[action]

@staticmethod
def _unique(values: list[str]) -> list[str]:
    """Preserve order while removing duplicate values."""
    return list(dict.fromkeys(values))

@staticmethod
def risk_level_from_string(value: str) -> RiskLevel:
    """Convert a risk-level string into a normalized enum."""
    return RiskLevel(value.lower())
```
