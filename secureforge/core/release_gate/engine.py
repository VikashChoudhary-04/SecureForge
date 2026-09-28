```python
# SecureForge release-gate engine

from __future__ import annotations

from secureforge.core.findings.models import Finding
from secureforge.core.policy.models import PolicyDecision
from secureforge.core.release_gate.models import ReleaseGateDecision
from secureforge.core.risk.models import RiskAssessment
from secureforge.regression.gate import RegressionGateDecision
from secureforge.validation.gate import ValidationGateDecision


class ReleaseGateEngine:
    """Evaluate the final SecureForge release decision."""

    def evaluate(
        self,
        *,
        findings: list[Finding],
        risk: RiskAssessment,
        policy: PolicyDecision,
        regression_gate: RegressionGateDecision | None = None,
        validation_gate: ValidationGateDecision | None = None,
    ) -> ReleaseGateDecision:
        """Evaluate all configured release controls."""
        del findings

        if validation_gate is not None:
            if validation_gate.blocked:
                return self._blocked_by_validation(
                    validation_gate
                )

            if validation_gate.status in {
                "review",
                "error",
            }:
                return self._review_by_validation(
                    validation_gate
                )

        if regression_gate is not None:
            if regression_gate.blocked:
                return self._blocked_by_regression(
                    regression_gate
                )

            if regression_gate.status in {
                "review",
                "error",
            }:
                return self._review_by_regression(
                    regression_gate
                )

        if not policy.allowed:
            return self._blocked_by_policy(
                policy
            )

        if not self._risk_allows_release(risk):
            return self._blocked_by_risk(
                risk
            )

        return ReleaseGateDecision(
            release_allowed=True,
            status="passed",
            reason=(
                "All configured release-gate controls passed."
            ),
        )

    @staticmethod
    def _blocked_by_validation(
        decision: ValidationGateDecision,
    ) -> ReleaseGateDecision:
        """Build a release-block decision from validation."""
        return ReleaseGateDecision(
            release_allowed=False,
            status="blocked",
            reason=(
                "Release blocked because security validation "
                "confirmed one or more findings: "
                f"{', '.join(decision.confirmed_findings)}."
            ),
        )

    @staticmethod
    def _review_by_validation(
        decision: ValidationGateDecision,
    ) -> ReleaseGateDecision:
        """Build a review decision from validation uncertainty."""
        details: list[str] = []

        if decision.inconclusive_findings:
            details.append(
                "inconclusive findings: "
                + ", ".join(
                    decision.inconclusive_findings
                )
            )

        if decision.errored_findings:
            details.append(
                "validation errors: "
                + ", ".join(
                    decision.errored_findings
                )
            )

        detail_text = (
            "; ".join(details)
            if details
            else "validation requires review"
        )

        return ReleaseGateDecision(
            release_allowed=False,
            status="review",
            reason=(
                "Release requires security review because "
                f"{detail_text}."
            ),
        )

    @staticmethod
    def _blocked_by_regression(
        decision: RegressionGateDecision,
    ) -> ReleaseGateDecision:
        """Build a release-block decision from regression."""
        failures = decision.failures

        return ReleaseGateDecision(
            release_allowed=False,
            status="blocked",
            reason=(
                "Release blocked because regression testing "
                "reported failures: "
                f"{', '.join(failures)}."
            ),
        )

    @staticmethod
    def _review_by_regression(
        decision: RegressionGateDecision,
    ) -> ReleaseGateDecision:
        """Build a review decision from regression uncertainty."""
        details = decision.failures

        if not details:
            details = (
                decision.skipped_tests
                if decision.skipped_tests
                else (
                    "Regression testing requires review.",
                )
            )

        return ReleaseGateDecision(
            release_allowed=False,
            status="review",
            reason=(
                "Release requires regression-test review: "
                f"{', '.join(details)}."
            ),
        )

    @staticmethod
    def _blocked_by_policy(
        policy: PolicyDecision,
    ) -> ReleaseGateDecision:
        """Build a release-block decision from policy."""
        return ReleaseGateDecision(
            release_allowed=False,
            status="blocked",
            reason=(
                "Release blocked by security policy: "
                f"{policy.reason}"
            ),
        )

    @staticmethod
    def _blocked_by_risk(
        risk: RiskAssessment,
    ) -> ReleaseGateDecision:
        """Build a release-block decision from risk."""
        return ReleaseGateDecision(
            release_allowed=False,
            status="blocked",
            reason=(
                "Release blocked because the calculated "
                "security risk exceeds the configured threshold."
            ),
        )

    @staticmethod
    def _risk_allows_release(
        risk: RiskAssessment,
    ) -> bool:
        """Return whether the risk assessment allows release."""
        return not risk.blocked


__all__ = [
    "ReleaseGateEngine",
]
```
