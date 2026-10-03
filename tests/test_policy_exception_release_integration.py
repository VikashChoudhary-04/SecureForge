"""Integration tests for policy exceptions and release gating."""

from __future__ import annotations

from secureforge.core.findings import Finding
from secureforge.core.policy import (
    PolicyAction,
    PolicyConfig,
    PolicyEngine,
    PolicyException,
    PolicyRule,
)
from secureforge.core.release_gate import (
    ReleaseDecision,
    ReleaseGateEngine,
    ReleaseGateInput,
)
from secureforge.core.risk import RiskAssessment


def build_finding(
    *,
    finding_id: str,
    severity: str,
) -> Finding:
    """Build a minimal finding for release-gate integration tests."""
    return Finding(
        finding_id=finding_id,
        title=f"{severity.title()} security finding",
        source="test",
        asset="securecommerce-api",
        severity=severity,
        confidence="high",
    )


def build_risk(
    finding_id: str,
) -> RiskAssessment:
    """Build a minimal risk assessment for policy evaluation."""
    return RiskAssessment(
        finding_id=finding_id,
        risk_score=90.0,
        contextual_risk="high",
    )


def test_exception_does_not_bypass_independent_blocking_finding() -> None:
    """An exception must not suppress an unrelated blocking finding."""
    exempted = build_finding(
        finding_id="SF-EXEMPT-001",
        severity="high",
    )
    blocking = build_finding(
        finding_id="SF-BLOCK-001",
        severity="high",
    )

    assessments = [
        build_risk(exempted.finding_id),
        build_risk(blocking.finding_id),
    ]

    policy = PolicyConfig(
        policy_id="exception-integration-policy",
        version="1.0",
        rules=[
            PolicyRule(
                rule_id="BLOCK-HIGH",
                name="Block high findings",
                description=(
                    "High severity findings block the release."
                ),
                severity="high",
                action=PolicyAction.BLOCK,
            ),
        ],
        exceptions=[
            PolicyException(
                exception_id="EXC-001",
                finding_id=exempted.finding_id,
                reason="Approved temporary exception.",
                approved_by="security-team",
            ),
        ],
    )

    policy_result = PolicyEngine().evaluate(
        [exempted, blocking],
        assessments,
        policy,
    )

    assert policy_result.exceptions_applied == [
        "EXC-001"
    ]
    assert policy_result.passed_findings == [
        exempted.finding_id
    ]
    assert policy_result.blocking_findings == [
        blocking.finding_id
    ]
    assert policy_result.decision.action == PolicyAction.BLOCK

    gate_input = ReleaseGateInput(
        application="SecureCommerce",
        version="1.0.0",
        commit_sha="exception-integration-test",
        policy_decision=ReleaseDecision(
            policy_result.decision.value
        ),
        blocking_findings=(
            policy_result.blocking_findings
        ),
        review_findings=(
            policy_result.review_findings
        ),
        exceptions_applied=(
            policy_result.exceptions_applied
        ),
    )

    release_result = ReleaseGateEngine().evaluate(
        gate_input
    )

    assert release_result.decision == ReleaseDecision.BLOCK
    assert release_result.is_blocked is True
    assert release_result.blocking_findings == [
        blocking.finding_id
    ]
    assert release_result.exceptions_applied == [
        "EXC-001"
    ]
    assert (
        "One or more findings triggered "
        "release-blocking policy conditions."
        in release_result.reasons
    )
    assert (
        "One or more configured policy exceptions "
        "were applied."
        in release_result.reasons
    )
