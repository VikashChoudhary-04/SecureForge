"""Individual policy matching and exception evaluation for SecureForge."""

from __future__ import annotations

from datetime import datetime, timezone

from secureforge.core.findings import Finding
from secureforge.core.risk import RiskAssessment

from .models import (
    PolicyAction,
    PolicyConfig,
    PolicyRule,
)


class PolicyEvaluator:
    """Evaluate individual policy rules and exceptions."""

    _action_priority = {
        PolicyAction.PASS: 0,
        PolicyAction.REVIEW: 1,
        PolicyAction.BLOCK: 2,
    }

    _severity_aliases = {
        "info": "informational",
        "informational": "informational",
    }

    def match_rule(
        self,
        finding: Finding,
        assessment: RiskAssessment,
        rules: list[PolicyRule],
    ) -> PolicyRule | None:
        """Return the highest-priority matching enabled rule."""
        matching_rules = [
            rule
            for rule in rules
            if rule.enabled
            and self.rule_matches(
                finding,
                assessment,
                rule,
            )
        ]

        if not matching_rules:
            return None

        return max(
            matching_rules,
            key=lambda rule: self.action_priority(
                rule.action
            ),
        )

    @classmethod
    def rule_matches(
        cls,
        finding: Finding,
        assessment: RiskAssessment,
        rule: PolicyRule,
    ) -> bool:
        """Determine whether a rule matches a finding."""
        if rule.severity is not None:
            finding_severity = cls._normalize_severity(
                finding.severity.value
            )

            rule_severity = cls._normalize_severity(
                rule.severity
            )

            if finding_severity != rule_severity:
                return False

        if rule.risk_level is not None:
            if (
                assessment.contextual_risk.value
                != rule.risk_level.strip().lower()
            ):
                return False

        return True

    @classmethod
    def _normalize_severity(
        cls,
        value: str,
    ) -> str:
        """Normalize policy severity values to the canonical vocabulary."""
        normalized = str(
            value
        ).strip().lower()

        return cls._severity_aliases.get(
            normalized,
            normalized,
        )

    @staticmethod
    def exception_applies(
        finding: Finding,
        policy: PolicyConfig,
    ) -> bool:
        """Determine whether an active policy exception applies."""
        return (
            PolicyEvaluator.find_exception(
                finding,
                policy,
            )
            is not None
        )

    @staticmethod
    def find_exception(
        finding: Finding,
        policy: PolicyConfig,
    ):
        """Return the first active exception matching a finding."""
        for exception in policy.exceptions:
            if not exception.enabled:
                continue

            if (
                exception.expires_at
                and not PolicyEvaluator._exception_is_active(
                    exception.expires_at
                )
            ):
                continue

            if exception.finding_id == finding.finding_id:
                return exception

            if (
                exception.requirement_id
                and finding.security_requirement
                and exception.requirement_id
                == finding.security_requirement
            ):
                return exception

        return None

    @staticmethod
    def _exception_is_active(
        expires_at: str,
    ) -> bool:
        """Return whether an exception has a valid future expiration."""
        try:
            expiration = datetime.fromisoformat(
                expires_at
            )
        except (
            TypeError,
            ValueError,
        ):
            return False

        if expiration.tzinfo is None:
            expiration = expiration.replace(
                tzinfo=timezone.utc
            )

        return expiration > datetime.now(
            timezone.utc
        )

    @classmethod
    def action_priority(
        cls,
        action: PolicyAction,
    ) -> int:
        """Return the priority of a policy action."""
        return cls._action_priority[action]

    @classmethod
    def highest_action(
        cls,
        actions: list[PolicyAction],
    ) -> PolicyAction:
        """Return the highest-priority action."""
        if not actions:
            return PolicyAction.PASS

        return max(
            actions,
            key=cls.action_priority,
        )


__all__ = [
    "PolicyEvaluator",
]
