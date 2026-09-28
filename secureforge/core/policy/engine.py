"""Policy evaluation engine for SecureForge."""

from __future__ import annotations

from collections.abc import Iterable

from secureforge.core.findings import Finding
from secureforge.core.risk import RiskAssessment

from .evaluator import PolicyEvaluator
from .models import (
PolicyAction,
PolicyConfig,
PolicyDecision,
PolicyEvaluation,
)

class PolicyEngine:
"""Evaluate security findings against a configured policy."""

    _decision_priority = {
        PolicyDecision.PASS: 0,
        PolicyDecision.REVIEW: 1,
        PolicyDecision.BLOCK: 2,
    }

    def __init__(
        self,
        evaluator: PolicyEvaluator | None = None,
    ) -> None:
        self.evaluator = evaluator or PolicyEvaluator()

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
        regression_failures = list(
        failed_regressions or []
        )

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
            assessment = assessment_map.get(
                finding.finding_id
            )

            if assessment is None:
                review_findings.append(
                    finding.finding_id
                )

                reasons.append(
                    f"No risk assessment was available for "
                    f"{finding.finding_id}."
                )

                final_decision = self._higher_decision(
                    final_decision,
                    PolicyDecision.REVIEW,
                )

                continue

            exception = self.evaluator.find_exception(
                finding,
                policy,
            )

            if exception is not None:
                exceptions_applied.append(
                    exception.exception_id
                )

                passed_findings.append(
                    finding.finding_id
                )

                reasons.append(
                    f"Policy exception "
                    f"'{exception.exception_id}' "
                f"was applied to {finding.finding_id}."
                )

                continue

            rule = self.evaluator.match_rule(
                finding,
                assessment,
                policy.rules,
            )

            if rule is None:
                review_findings.append(
                    finding.finding_id
                )

                reasons.append(
                    f"No explicit policy rule matched "
                    f"{finding.finding_id}; review required."
                )

                final_decision = self._higher_decision(
                    final_decision,
                    PolicyDecision.REVIEW,
                )

                continue

            triggered_rules.append(
                rule.rule_id
            )

            decision = self._action_to_decision(
                rule.action
            )

            if decision == PolicyDecision.BLOCK:
                blocking_findings.append(
                    finding.finding_id
                )

                reasons.append(
                    f"{finding.finding_id} triggered "
                    f"blocking rule {rule.rule_id}."
                )

            elif decision == PolicyDecision.REVIEW:
                review_findings.append(
                    finding.finding_id
                )

                reasons.append(
                    f"{finding.finding_id} triggered "
                    f"review rule {rule.rule_id}."
                )

            else:
                passed_findings.append(
                    finding.finding_id
                )

                reasons.append(
                    f"{finding.finding_id} passed "
                    f"rule {rule.rule_id}."
                )

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
                    "Security regression tests failed and "
                    "require review: "
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
                    f"{tool_errors} security tool execution "
                    "error(s) were encountered."
                )

            else:
                final_decision = self._higher_decision(
                    final_decision,
                    PolicyDecision.REVIEW,
                )

                reasons.append(
                    f"{tool_errors} security tool execution "
                    "error(s) require review."
                )

        if not reasons:
            reasons.append(
                "No policy conditions were triggered."
            )

        return PolicyEvaluation(
            decision=final_decision,
            triggered_rules=self._unique(
                triggered_rules
            ),
            blocking_findings=self._unique(
                blocking_findings
            ),
            review_findings=self._unique(
                review_findings
            ),
            passed_findings=self._unique(
                passed_findings
            ),
            exceptions_applied=self._unique(
                exceptions_applied
            ),
            reasons=reasons,
            policy_id=policy.policy_id,
            policy_version=policy.version,
        )

    @staticmethod
    def _action_to_decision(
        action: PolicyAction,
    ) -> PolicyDecision:
        """Convert a policy action into a policy decision."""
        return PolicyDecision(
            action.value
        )
    
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
    def _unique(
        values: list[str],
    ) -> list[str]:
        """Preserve order while removing duplicate values."""
        return list(
            dict.fromkeys(values)
        )
    
    @staticmethod
    def risk_level_from_string(
        value: str,
    ):
        """Convert a risk-level string into a normalized enum."""
        from secureforge.core.risk import RiskLevel
    
        return RiskLevel(
            value.strip().lower()
        )
