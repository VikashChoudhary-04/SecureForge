# SecureForge release-gate validation tests

from secureforge.core.findings.models import Finding, Severity
from secureforge.core.policy.models import PolicyDecision
from secureforge.core.release_gate.engine import ReleaseGateEngine
from secureforge.core.risk.models import RiskAssessment
from secureforge.validation.gate import ValidationGateDecision


def _finding() -> Finding:
    return Finding(
        finding_id="TEST-001",
        title="Test security finding",
        source="test",
        severity=Severity.LOW,
        description="Controlled test finding.",
    )


def _risk() -> RiskAssessment:
    return RiskAssessment(
        score=0.0,
        level="low",
        blocked=False,
        factors=[],
        evaluated_at="2026-09-28T00:00:00+00:00",
    )


def _policy() -> PolicyDecision:
    return PolicyDecision(
        allowed=True,
        status="passed",
        reason="Policy passed.",
        actions=[],
    )


def test_validation_block_produces_blocked_release() -> None:
    engine = ReleaseGateEngine()

    validation_gate = ValidationGateDecision(
        allowed=False,
        status="blocked",
        reason="Confirmed security findings require remediation.",
        confirmed_findings=("TEST-001",),
        unresolved_findings=("TEST-001",),
        remediation_verified=(),
        inconclusive_findings=(),
        errored_findings=(),
    )

    decision = engine.evaluate(
        findings=[_finding()],
        risk=_risk(),
        policy=_policy(),
        validation_gate=validation_gate,
    )

    assert decision.release_allowed is False
    assert decision.status == "blocked"
    assert decision.blocked is True


def test_validation_review_produces_review_release() -> None:
    engine = ReleaseGateEngine()

    validation_gate = ValidationGateDecision(
        allowed=True,
        status="review",
        reason="Validation evidence is inconclusive.",
        confirmed_findings=(),
        unresolved_findings=(),
        remediation_verified=(),
        inconclusive_findings=("TEST-001",),
        errored_findings=(),
    )

    decision = engine.evaluate(
        findings=[_finding()],
        risk=_risk(),
        policy=_policy(),
        validation_gate=validation_gate,
    )

    assert decision.release_allowed is True
    assert decision.status == "review"
    assert decision.review_required is True
    assert decision.blocked is False


def test_validation_pass_produces_passed_release() -> None:
    engine = ReleaseGateEngine()

    validation_gate = ValidationGateDecision(
        allowed=True,
        status="passed",
        reason="Validation completed successfully.",
        confirmed_findings=(),
        unresolved_findings=(),
        remediation_verified=("TEST-001",),
        inconclusive_findings=(),
        errored_findings=(),
    )

    decision = engine.evaluate(
        findings=[_finding()],
        risk=_risk(),
        policy=_policy(),
        validation_gate=validation_gate,
    )

    assert decision.release_allowed is True
    assert decision.status == "passed"
    assert decision.passed is True
    assert decision.blocked is False

