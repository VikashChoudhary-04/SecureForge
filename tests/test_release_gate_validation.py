```python
# Release-gate validation integration tests

from __future__ import annotations

from secureforge.core.policy.models import PolicyDecision
from secureforge.core.release_gate.engine import ReleaseGateEngine
from secureforge.core.risk.models import RiskAssessment
from secureforge.validation.gate import ValidationGateDecision


def make_policy(
    *,
    allowed: bool = True,
) -> PolicyDecision:
    """Create a controlled policy decision."""
    return PolicyDecision(
        allowed=allowed,
        status=(
            "passed"
            if allowed
            else "blocked"
        ),
        reason=(
            "Policy passed."
            if allowed
            else "Policy blocked the release."
        ),
    )


def make_risk(
    *,
    blocked: bool = False,
) -> RiskAssessment:
    """Create a controlled risk assessment."""
    return RiskAssessment(
        score=0.0,
        level="low",
        blocked=blocked,
        factors={},
    )


def make_validation_gate(
    *,
    status: str,
    allowed: bool,
    confirmed: tuple[str, ...] = (),
    inconclusive: tuple[str, ...] = (),
    errors: tuple[str, ...] = (),
) -> ValidationGateDecision:
    """Create a controlled validation-gate decision."""
    return ValidationGateDecision(
        allowed=allowed,
        status=status,
        reason="Controlled validation result.",
        confirmed_findings=confirmed,
        unresolved_findings=confirmed,
        remediation_verified=(),
        inconclusive_findings=inconclusive,
        errored_findings=errors,
    )


def test_confirmed_validation_blocks_release():
    engine = ReleaseGateEngine()

    decision = engine.evaluate(
        findings=[],
        risk=make_risk(),
        policy=make_policy(),
        validation_gate=make_validation_gate(
            status="blocked",
            allowed=False,
            confirmed=("BOLA-001",),
        ),
    )

    assert decision.release_allowed is False
    assert decision.status == "blocked"
    assert "BOLA-001" in decision.reason


def test_inconclusive_validation_requires_review():
    engine = ReleaseGateEngine()

    decision = engine.evaluate(
        findings=[],
        risk=make_risk(),
        policy=make_policy(),
        validation_gate=make_validation_gate(
            status="review",
            allowed=True,
            inconclusive=("SQLI-001",),
        ),
    )

    assert decision.release_allowed is False
    assert decision.status == "review"
    assert "SQLI-001" in decision.reason


def test_validation_error_requires_review():
    engine = ReleaseGateEngine()

    decision = engine.evaluate(
        findings=[],
        risk=make_risk(),
        policy=make_policy(),
        validation_gate=make_validation_gate(
            status="error",
            allowed=True,
            errors=("BOLA-001",),
        ),
    )

    assert decision.release_allowed is False
    assert decision.status == "review"
    assert "BOLA-001" in decision.reason


def test_passed_validation_allows_other_controls_to_continue():
    engine = ReleaseGateEngine()

    decision = engine.evaluate(
        findings=[],
        risk=make_risk(),
        policy=make_policy(),
        validation_gate=make_validation_gate(
            status="passed",
            allowed=True,
        ),
    )

    assert decision.release_allowed is True
    assert decision.status == "passed"


def test_policy_still_blocks_after_validation_passes():
    engine = ReleaseGateEngine()

    decision = engine.evaluate(
        findings=[],
        risk=make_risk(),
        policy=make_policy(
            allowed=False
        ),
        validation_gate=make_validation_gate(
            status="passed",
            allowed=True,
        ),
    )

    assert decision.release_allowed is False
    assert decision.status == "blocked"
    assert "policy" in decision.reason.lower()


def test_risk_still_blocks_after_validation_passes():
    engine = ReleaseGateEngine()

    decision = engine.evaluate(
        findings=[],
        risk=make_risk(
            blocked=True
        ),
        policy=make_policy(),
        validation_gate=make_validation_gate(
            status="passed",
            allowed=True,
        ),
    )

    assert decision.release_allowed is False
    assert decision.status == "blocked"
    assert "risk" in decision.reason.lower()


def test_release_gate_can_pass_without_validation():
    engine = ReleaseGateEngine()

    decision = engine.evaluate(
        findings=[],
        risk=make_risk(),
        policy=make_policy(),
    )

    assert decision.release_allowed is True
    assert decision.status == "passed"
```
