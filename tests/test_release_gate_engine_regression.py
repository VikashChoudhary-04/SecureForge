"""Tests for regression integration in the release gate engine."""

from secureforge.core.release_gate.engine import (
    ReleaseGateEngine,
)
from secureforge.core.release_gate.models import (
    ReleaseGateStatus,
)
from secureforge.core.release_gate.regression import (
    RegressionGateResult,
)
from secureforge.core.risk.models import (
    RiskAssessment,
)
from secureforge.core.policy.models import (
    PolicyDecision,
)


def test_release_gate_allows_when_regression_passes() -> None:
    """Allow the policy decision when regression testing passes."""
    engine = ReleaseGateEngine()

    risk = RiskAssessment(
        score=0.0,
        highest_severity="info",
        finding_count=0,
        evaluated_at="2026-09-27T10:00:00+00:00",
    )

    policy = PolicyDecision(
        policy_name="default",
        action="pass",
        allowed=True,
        reason="No policy violations.",
        violations=[],
    )

    regression = RegressionGateResult(
        allowed=True,
        blocked=False,
        status="passed",
        reason="All security regression tests passed.",
        failures=(),
        skipped_tests=(),
    )

    decision = engine.evaluate(
        risk=risk,
        policy=policy,
        regression=regression,
    )

    assert decision.release_allowed is True
    assert decision.status == ReleaseGateStatus.PASSED


def test_release_gate_blocks_when_regression_blocks() -> None:
    """Block a release when regression testing blocks it."""
    engine = ReleaseGateEngine()

    risk = RiskAssessment(
        score=0.0,
        highest_severity="info",
        finding_count=0,
        evaluated_at="2026-09-27T10:00:00+00:00",
    )

    policy = PolicyDecision(
        policy_name="default",
        action="pass",
        allowed=True,
        reason="No policy violations.",
        violations=[],
    )

    regression = RegressionGateResult(
        allowed=False,
        blocked=True,
        status="failed",
        reason="BOLA-001 failed.",
        failures=("BOLA-001",),
        skipped_tests=(),
    )

    decision = engine.evaluate(
        risk=risk,
        policy=policy,
        regression=regression,
    )

    assert decision.release_allowed is False
    assert decision.status == ReleaseGateStatus.BLOCKED
    assert "Regression gate blocked the release" in (
        decision.reason
    )
    assert "BOLA-001" in decision.reason


def test_release_gate_without_regression_preserves_policy() -> None:
    """Preserve normal policy evaluation when no regression is supplied."""
    engine = ReleaseGateEngine()

    risk = RiskAssessment(
        score=0.0,
        highest_severity="info",
        finding_count=0,
        evaluated_at="2026-09-27T10:00:00+00:00",
    )

    policy = PolicyDecision(
        policy_name="default",
        action="pass",
        allowed=True,
        reason="No policy violations.",
        violations=[],
    )

    decision = engine.evaluate(
        risk=risk,
        policy=policy,
    )

    assert decision.release_allowed is True
    assert decision.status == ReleaseGateStatus.PASSED


def test_regression_gate_result_serializes() -> None:
    """Serialize regression results for release-gate consumers."""
    result = RegressionGateResult(
        allowed=False,
        blocked=True,
        status="failed",
        reason="Security regression failed.",
        failures=("BOLA-001", "SQLI-001"),
        skipped_tests=("XSS-001",),
    )

    payload = result.to_dict()

    assert payload["allowed"] is False
    assert payload["blocked"] is True
    assert payload["status"] == "failed"
    assert payload["failures"] == [
        "BOLA-001",
        "SQLI-001",
    ]
    assert payload["skipped_tests"] == [
        "XSS-001"
    ]
