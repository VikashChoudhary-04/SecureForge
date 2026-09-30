"""Tests for the SecureForge release decision evaluator."""

from secureforge.core.release_gate.evaluator import (
    ReleaseDecisionEvaluator,
)
from secureforge.core.release_gate.models import (
    ReleaseDecision,
    ReleaseGateInput,
)


def build_input(
    *,
    policy_decision: ReleaseDecision = ReleaseDecision.PASS,
    blocking_findings: list[str] | None = None,
    review_findings: list[str] | None = None,
    failed_regressions: list[str] | None = None,
    tool_errors: list[str] | None = None,
    exceptions_applied: list[str] | None = None,
) -> ReleaseGateInput:
    """Create a representative release-gate input."""
    return ReleaseGateInput(
        application="SecureCommerce",
        version="1.0.0",
        commit_sha="abc123",
        policy_decision=policy_decision,
        blocking_findings=blocking_findings or [],
        review_findings=review_findings or [],
        failed_regressions=failed_regressions or [],
        tool_errors=tool_errors or [],
        exceptions_applied=exceptions_applied or [],
    )


def test_pass_policy_produces_pass() -> None:
    """Verify a clean policy result produces PASS."""
    evaluator = ReleaseDecisionEvaluator()

    decision, reasons = evaluator.evaluate(
        build_input()
    )

    assert decision == ReleaseDecision.PASS
    assert reasons == [
        "No configured release-blocking or review "
        "conditions were triggered."
    ]


def test_review_policy_produces_review() -> None:
    """Verify a REVIEW policy result produces REVIEW."""
    evaluator = ReleaseDecisionEvaluator()

    decision, reasons = evaluator.evaluate(
        build_input(
            policy_decision=ReleaseDecision.REVIEW
        )
    )

    assert decision == ReleaseDecision.REVIEW
    assert reasons == [] or reasons


def test_block_policy_produces_block() -> None:
    """Verify a BLOCK policy result produces BLOCK."""
    evaluator = ReleaseDecisionEvaluator()

    decision, reasons = evaluator.evaluate(
        build_input(
            policy_decision=ReleaseDecision.BLOCK
        )
    )

    assert decision == ReleaseDecision.BLOCK
    assert reasons == [] or reasons


def test_blocking_findings_force_block() -> None:
    """Verify blocking findings always produce BLOCK."""
    evaluator = ReleaseDecisionEvaluator()

    decision, reasons = evaluator.evaluate(
        build_input(
            blocking_findings=[
                "SF-001"
            ]
        )
    )

    assert decision == ReleaseDecision.BLOCK
    assert (
        "One or more findings triggered "
        "release-blocking policy conditions."
        in reasons
    )


def test_failed_regression_forces_block() -> None:
    """Verify failed security regressions produce BLOCK."""
    evaluator = ReleaseDecisionEvaluator()

    decision, reasons = evaluator.evaluate(
        build_input(
            failed_regressions=[
                "BOLA-001"
            ]
        )
    )

    assert decision == ReleaseDecision.BLOCK
    assert (
        "One or more security regression tests failed."
        in reasons
    )


def test_tool_error_requires_review() -> None:
    """Verify tool errors raise the decision to REVIEW."""
    evaluator = ReleaseDecisionEvaluator()

    decision, reasons = evaluator.evaluate(
        build_input(
            tool_errors=[
                "Nmap execution failed."
            ]
        )
    )

    assert decision == ReleaseDecision.REVIEW
    assert (
        "One or more security integrations "
        "reported execution errors."
        in reasons
    )


def test_review_findings_require_review() -> None:
    """Verify review findings produce REVIEW."""
    evaluator = ReleaseDecisionEvaluator()

    decision, reasons = evaluator.evaluate(
        build_input(
            review_findings=[
                "SF-002"
            ]
        )
    )

    assert decision == ReleaseDecision.REVIEW
    assert (
        "One or more findings require security review."
        in reasons
    )


def test_policy_pass_with_exception_records_reason() -> None:
    """Verify applied exceptions are recorded."""
    evaluator = ReleaseDecisionEvaluator()

    decision, reasons = evaluator.evaluate(
        build_input(
            exceptions_applied=[
                "EXC-001"
            ]
        )
    )

    assert decision == ReleaseDecision.PASS
    assert (
        "One or more configured policy exceptions "
        "were applied."
        in reasons
    )


def test_block_takes_precedence_over_review() -> None:
    """Verify BLOCK outranks REVIEW."""
    evaluator = ReleaseDecisionEvaluator()

    decision, _ = evaluator.evaluate(
        build_input(
            policy_decision=ReleaseDecision.REVIEW,
            review_findings=[
                "SF-002"
            ],
            blocking_findings=[
                "SF-001"
            ],
        )
    )

    assert decision == ReleaseDecision.BLOCK


def test_failed_regression_takes_precedence_over_review() -> None:
    """Verify regression failure outranks review."""
    evaluator = ReleaseDecisionEvaluator()

    decision, _ = evaluator.evaluate(
        build_input(
            policy_decision=ReleaseDecision.REVIEW,
            review_findings=[
                "SF-002"
            ],
            failed_regressions=[
                "SQLI-001"
            ],
        )
    )

    assert decision == ReleaseDecision.BLOCK


def test_blocking_finding_takes_precedence_over_tool_error() -> None:
    """Verify BLOCK outranks tool-error REVIEW."""
    evaluator = ReleaseDecisionEvaluator()

    decision, _ = evaluator.evaluate(
        build_input(
            tool_errors=[
                "DAST failed."
            ],
            blocking_findings=[
                "SF-001"
            ],
        )
    )

    assert decision == ReleaseDecision.BLOCK


def test_tool_error_takes_precedence_over_pass() -> None:
    """Verify tool errors raise PASS to REVIEW."""
    evaluator = ReleaseDecisionEvaluator()

    decision, _ = evaluator.evaluate(
        build_input(
            policy_decision=ReleaseDecision.PASS,
            tool_errors=[
                "SCA failed."
            ],
        )
    )

    assert decision == ReleaseDecision.REVIEW


def test_from_policy_decision_converts_values() -> None:
    """Verify policy decisions map to release decisions."""
    evaluator = ReleaseDecisionEvaluator()

    assert evaluator.from_policy_decision(
        ReleaseDecision.PASS
    ) == ReleaseDecision.PASS

    assert evaluator.from_policy_decision(
        ReleaseDecision.REVIEW
    ) == ReleaseDecision.REVIEW

    assert evaluator.from_policy_decision(
        ReleaseDecision.BLOCK
    ) == ReleaseDecision.BLOCK


def test_higher_decision_prefers_block() -> None:
    """Verify BLOCK has the highest precedence."""
    evaluator = ReleaseDecisionEvaluator()

    assert evaluator.higher_decision(
        ReleaseDecision.PASS,
        ReleaseDecision.BLOCK,
    ) == ReleaseDecision.BLOCK

    assert evaluator.higher_decision(
        ReleaseDecision.REVIEW,
        ReleaseDecision.BLOCK,
    ) == ReleaseDecision.BLOCK


def test_higher_decision_prefers_review_over_pass() -> None:
    """Verify REVIEW outranks PASS."""
    evaluator = ReleaseDecisionEvaluator()

    assert evaluator.higher_decision(
        ReleaseDecision.PASS,
        ReleaseDecision.REVIEW,
    ) == ReleaseDecision.REVIEW


def test_higher_decision_preserves_existing_block() -> None:
    """Verify a lower-priority candidate cannot downgrade BLOCK."""
    evaluator = ReleaseDecisionEvaluator()

    assert evaluator.higher_decision(
        ReleaseDecision.BLOCK,
        ReleaseDecision.PASS,
    ) == ReleaseDecision.BLOCK

    assert evaluator.higher_decision(
        ReleaseDecision.BLOCK,
        ReleaseDecision.REVIEW,
    ) == ReleaseDecision.BLOCK


def test_multiple_conditions_are_all_explained() -> None:
    """Verify all relevant release conditions are reported."""
    evaluator = ReleaseDecisionEvaluator()

    decision, reasons = evaluator.evaluate(
        build_input(
            review_findings=[
                "SF-002"
            ],
            failed_regressions=[
                "BOLA-001"
            ],
            tool_errors=[
                "DAST failed."
            ],
            exceptions_applied=[
                "EXC-001"
            ],
        )
    )

    assert decision == ReleaseDecision.BLOCK

    assert (
        "One or more security regression tests failed."
        in reasons
    )

    assert (
        "One or more security integrations "
        "reported execution errors."
        in reasons
    )

    assert (
        "One or more findings require security review."
        in reasons
    )

    assert (
        "One or more configured policy exceptions "
        "were applied."
        in reasons
    )
