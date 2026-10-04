"""Regression tests for release-gate validation precedence."""

from __future__ import annotations

from types import SimpleNamespace

from secureforge.core.release_gate import (
    ReleaseDecision,
    ReleaseGateEngine,
)


def _validation_gate(
    status: str,
) -> SimpleNamespace:
    """Build a minimal validation-gate object for precedence tests."""
    return SimpleNamespace(
        status=status,
        blocked=status == "blocked",
        reason=f"Validation status: {status}.",
    )


def _policy(
    decision: ReleaseDecision,
) -> SimpleNamespace:
    """Build a minimal policy decision object."""
    return SimpleNamespace(
        action=decision,
    )


def test_policy_block_cannot_be_downgraded_by_validation_pass() -> None:
    """A successful validation must not override a blocking policy decision."""
    engine = ReleaseGateEngine()

    result = engine.evaluate(
        policy=_policy(ReleaseDecision.BLOCK),
        validation_gate=_validation_gate("passed"),
    )

    assert result.decision == ReleaseDecision.BLOCK


def test_policy_review_cannot_be_downgraded_by_validation_pass() -> None:
    """A successful validation must not override a review policy decision."""
    engine = ReleaseGateEngine()

    result = engine.evaluate(
        policy=_policy(ReleaseDecision.REVIEW),
        validation_gate=_validation_gate("passed"),
    )

    assert result.decision == ReleaseDecision.REVIEW


def test_policy_pass_with_validation_pass_produces_pass() -> None:
    """A successful validation preserves an otherwise passing release."""
    engine = ReleaseGateEngine()

    result = engine.evaluate(
        policy=_policy(ReleaseDecision.PASS),
        validation_gate=_validation_gate("passed"),
    )

    assert result.decision == ReleaseDecision.PASS


def test_validation_block_produces_block() -> None:
    """A blocking validation result must block the release."""
    engine = ReleaseGateEngine()

    result = engine.evaluate(
        policy=_policy(ReleaseDecision.PASS),
        validation_gate=_validation_gate("blocked"),
    )

    assert result.decision == ReleaseDecision.BLOCK
