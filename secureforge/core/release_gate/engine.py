```python id="7x4m2p"
"""Release-gate evaluation for SecureForge."""

from __future__ import annotations

from secureforge.core.policy.models import PolicyDecision
from secureforge.core.release_gate.models import (
    ReleaseGateDecision,
)
from secureforge.core.risk.models import RiskAssessment
from secureforge.core.findings.models import Finding
from secureforge.regression.gate import RegressionGateDecision
from secureforge.validation.gate import ValidationGateDecision


class ReleaseGateEngine:
    """Evaluate whether a release may proceed."""

    def evaluate(
        self,
        *,
        findings: list[Finding],
        risk: RiskAssessment,
        policy: PolicyDecision,
        regression_gate: RegressionGateDecision | None = None,
        validation_gate: ValidationGateDecision | None = None,
    ) -> ReleaseGateDecision:
        """Evaluate policy, validation and regression controls."""
        if validation_gate is not None and validation_gate.blocked:
            return self._blocked_by_validation(
                validation_gate
            )

        if regression_gate is not None and regression_gate.blocked:
            return self._blocked_by_regression(
                regression_gate
            )

        if not policy.allowed:
            return self._blocked_by_policy(policy)

        if not self._risk_allows_release(risk):
            return self._blocked_by_risk(risk)

        return ReleaseGateDecision(
            release_allowed=True,
            status="passed",
            reason="All configured release-gate controls passed.",
        )

    @staticmethod
    def _blocked_by_validation(
        decision: ValidationGateDecision,
    ) -> ReleaseGateDecision:
        """Build a release decision from validation failure."""
        return ReleaseGateDecision(
            release_allowed=False,
            status="blocked",
            reason=(
                "Security validation did not satisfy the release gate: "
                f"{decision.reason}"
            ),
        )

    @staticmethod
    def _blocked_by_regression(
        decision: RegressionGateDecision,
    ) -> ReleaseGateDecision:
        """Build a release decision from regression failure."""
        return ReleaseGateDecision(
            release_allowed=False,
            status="blocked",
            reason=(
                "Regression testing did not satisfy the release gate: "
                f"{decision.reason}"
            ),
        )

    @staticmethod
    def _blocked_by_policy(
        policy: PolicyDecision,
    ) -> ReleaseGateDecision:
        """Build a release decision from policy failure."""
        return ReleaseGateDecision(
            release_allowed=False,
            status="blocked",
            reason=(
                "Security policy did not satisfy the release gate: "
                f"{policy.reason}"
            ),
        )

    @staticmethod
    def _blocked_by_risk(
        risk: RiskAssessment,
    ) -> ReleaseGateDecision:
        """Build a release decision from risk evaluation."""
        return ReleaseGateDecision(
            release_allowed=False,
            status="blocked",
            reason=(
                "Security risk did not satisfy the release gate: "
                f"{risk.reason}"
            ),
        )

    @staticmethod
    def _risk_allows_release(
        risk: RiskAssessment,
    ) -> bool:
        """Determine whether the evaluated risk permits release."""
        return not risk.blocked
```
