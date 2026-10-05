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
from secureforge.core.scan.security_pipeline import SecurityPipeline


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
    assert policy_result.decision.exception_findings == [
        exempted.finding_id
    ]

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


def test_pipeline_exception_prevents_exempted_critical_finding_from_blocking() -> None:
    """An exception must prevent its critical finding from independently blocking."""
    exempted = build_finding(
        finding_id="CRIT-EXEMPT-001",
        severity="critical",
    )

    policy = PolicyConfig(
        policy_id="critical-exception-policy",
        version="1.0",
        rules=[
            PolicyRule(
                rule_id="BLOCK-CRITICAL",
                name="Block critical findings",
                description=(
                    "Critical findings block the release."
                ),
                severity="critical",
                action=PolicyAction.BLOCK,
            ),
        ],
        exceptions=[
            PolicyException(
                exception_id="EXC-CRITICAL-001",
                finding_id=exempted.finding_id,
                reason="Approved exception for regression testing.",
                approved_by="security-team",
            ),
        ],
    )

    result = SecurityPipeline().evaluate(
        [exempted],
        policy=policy,
    )

    assert result.policy is not None
    assert result.policy.action == PolicyAction.PASS
    assert result.policy.allowed is True
    assert result.policy.violations == []
    assert result.policy.exception_findings == [
        exempted.finding_id
    ]
    assert result.policy.risk_blocking_findings == []

    assert result.release_gate is not None
    assert result.release_gate.decision == ReleaseDecision.PASS
    assert result.release_gate.blocking_findings == []
    assert result.release_gate.exceptions_applied == [
        "EXC-CRITICAL-001"
    ]


def test_pipeline_exception_does_not_bypass_independent_critical_finding() -> None:
    """An exception must not suppress an unrelated critical finding."""
    exempted = build_finding(
        finding_id="CRIT-EXEMPT-002",
        severity="critical",
    )
    blocking = build_finding(
        finding_id="CRIT-BLOCK-001",
        severity="critical",
    )

    policy = PolicyConfig(
        policy_id="mixed-critical-exception-policy",
        version="1.0",
        rules=[
            PolicyRule(
                rule_id="BLOCK-CRITICAL",
                name="Block critical findings",
                description=(
                    "Critical findings block the release."
                ),
                severity="critical",
                action=PolicyAction.BLOCK,
            ),
        ],
        exceptions=[
            PolicyException(
                exception_id="EXC-CRITICAL-002",
                finding_id=exempted.finding_id,
                reason="Approved exception for regression testing.",
                approved_by="security-team",
            ),
        ],
    )

    result = SecurityPipeline().evaluate(
        [exempted, blocking],
        policy=policy,
    )

    assert result.policy is not None
    assert result.policy.action == PolicyAction.BLOCK
    assert result.policy.exception_findings == [
        exempted.finding_id
    ]
    assert result.policy.risk_blocking_findings == [
        blocking.finding_id
    ]

    assert result.release_gate is not None
    assert result.release_gate.decision == ReleaseDecision.BLOCK

    assert result.release_gate.blocking_findings == [
        blocking.finding_id,
        "risk-threshold",
    ]

    assert result.release_gate.exceptions_applied == [
        "EXC-CRITICAL-002"
    ]


def test_pipeline_preserves_high_policy_blocking_finding_in_release_gate() -> None:
    """A policy-blocking HIGH finding must remain visible in the release record."""
    finding = build_finding(
        finding_id="HIGH-POLICY-BLOCK-001",
        severity="high",
    )

    policy = PolicyConfig(
        policy_id="high-block-policy",
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
    )

    result = SecurityPipeline().evaluate(
        [finding],
        policy=policy,
    )

    assert result.policy is not None
    assert result.policy.action == PolicyAction.BLOCK
    assert result.policy.blocking_findings == [
        finding.finding_id
    ]

    assert result.release_gate is not None
    assert result.release_gate.decision == ReleaseDecision.BLOCK
    assert result.release_gate.blocking_findings == [
        finding.finding_id
    ]


def test_pipeline_preserves_medium_policy_review_finding_in_release_gate() -> None:
    """A policy-review MEDIUM finding must remain visible in the release record."""
    finding = build_finding(
        finding_id="MEDIUM-POLICY-REVIEW-001",
        severity="medium",
    )

    policy = PolicyConfig(
        policy_id="medium-review-policy",
        version="1.0",
        rules=[
            PolicyRule(
                rule_id="REVIEW-MEDIUM",
                name="Review medium findings",
                description=(
                    "Medium severity findings require security review."
                ),
                severity="medium",
                action=PolicyAction.REVIEW,
            ),
        ],
    )

    result = SecurityPipeline().evaluate(
        [finding],
        policy=policy,
    )

    assert result.policy is not None
    assert result.policy.action == PolicyAction.REVIEW
    assert result.policy.review_findings == [
        finding.finding_id
    ]

    assert result.release_gate is not None
    assert result.release_gate.decision == ReleaseDecision.REVIEW
    assert result.release_gate.review_findings == [
        finding.finding_id
    ]
