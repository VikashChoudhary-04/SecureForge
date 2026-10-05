"""Regression tests for release-gate engine behavior."""

from __future__ import annotations

from secureforge.core.policy.models import PolicyDecision
from secureforge.core.release_gate.engine import ReleaseGateEngine
from secureforge.core.release_gate.models import ReleaseGateStatus
from secureforge.core.release_gate.regression import RegressionGateResult


def test_release_gate_blocks_when_regression_blocks() -> None:
    """Block the release when the regression gate blocks."""
    engine = ReleaseGateEngine()

    policy = PolicyDecision(
        policy_name="regression-policy",
        action="pass",
        allowed=True,
        reason="No policy violations.",
        violations=[],
    )

    regression = RegressionGateResult(
        allowed=False,
        blocked=True,
        status="failed",
        reason="Security regression failed.",
        failures=("BOLA-001",),
        skipped_tests=(),
    )

    decision = engine.evaluate(
        policy=policy,
        regression=regression,
    )

    assert decision.decision.value == "block"
    assert "BOLA-001" in decision.reason


def test_blocked_regression_preserves_release_gate_evidence() -> None:
    """Preserve release evidence when regression testing blocks."""
    engine = ReleaseGateEngine()

    policy = PolicyDecision(
        policy_name="evidence-policy",
        action="review",
        allowed=False,
        reason="Security findings require review.",
        violations=["SF-001", "SF-002"],
        blocking_findings=["SF-001"],
        review_findings=["SF-002"],
        exceptions_applied=["EXC-001"],
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
        policy=policy,
        regression=regression,
    )

    assert decision.decision.value == "block"
    assert decision.blocking_findings == ["SF-001"]
    assert decision.review_findings == ["SF-002"]
    assert decision.failed_regressions == ["BOLA-001"]
    assert decision.exceptions_applied == ["EXC-001"]


def test_release_gate_without_regression_preserves_policy() -> None:
    """Preserve normal policy evaluation when no regression is supplied."""
    engine = ReleaseGateEngine()

    policy = PolicyDecision(
        policy_name="passing-policy",
        action="pass",
        allowed=True,
        reason="No policy violations.",
        violations=[],
    )

    decision = engine.evaluate(
        policy=policy,
    )

    assert decision.release_allowed is True
    assert decision.status == ReleaseGateStatus.PASSED


def test_release_gate_allows_passing_regression() -> None:
    """Allow the release when policy and regression checks pass."""
    engine = ReleaseGateEngine()

    policy = PolicyDecision(
        policy_name="passing-policy",
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
        policy=policy,
        regression=regression,
    )

    assert decision.release_allowed is True
    assert decision.status == ReleaseGateStatus.PASSED


def test_release_gate_review_policy_with_passing_regression() -> None:
    """Preserve policy review when regression testing passes."""
    engine = ReleaseGateEngine()

    policy = PolicyDecision(
        policy_name="review-policy",
        action="review",
        allowed=False,
        reason="Security findings require review.",
        violations=["SF-001"],
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
        policy=policy,
        regression=regression,
    )

    assert decision.release_allowed is True
    assert decision.decision.value == "review"


def test_release_gate_passes_when_risk_is_not_blocked() -> None:
    """Allow the release when risk assessment is not blocked."""
    engine = ReleaseGateEngine()

    policy = PolicyDecision(
        policy_name="risk-policy",
        action="pass",
        allowed=True,
        reason="No policy violations.",
        violations=[],
    )

    risk = type(
        "Risk",
        (),
        {
            "blocked": False,
            "finding_id": "SF-001",
        },
    )()

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
        "XSS-001",
    ]

