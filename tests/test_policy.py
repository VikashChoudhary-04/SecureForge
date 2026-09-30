"""Tests for SecureForge policy evaluation."""

from secureforge.core.findings import (
    Confidence,
    Finding,
    Severity,
)
from secureforge.core.policy import (
    PolicyAction,
    PolicyConfig,
    PolicyDecision,
    PolicyEngine,
    PolicyException,
    PolicyRule,
)
from secureforge.core.risk import (
    RiskAssessment,
    RiskContext,
    RiskLevel,
)


def build_finding(
    *,
    finding_id: str = "SF-0001",
    severity: Severity = Severity.HIGH,
) -> Finding:
    """Create a representative finding."""
    return Finding(
        finding_id=finding_id,
        title="Broken Object Level Authorization",
        source="dast",
        application="SecureCommerce",
        asset="securecommerce-api",
        endpoint="/api/orders/1002",
        parameter="id",
        cwe="CWE-639",
        owasp="API1",
        security_requirement="SF-AUTHZ-001",
        severity=severity,
        confidence=Confidence.CONFIRMED,
        description="A user can access another user's order.",
        impact="Unauthorized access to protected order data.",
        remediation="Enforce object-level authorization.",
    )


def build_assessment(
    finding: Finding,
    *,
    risk_level: RiskLevel = RiskLevel.HIGH,
) -> RiskAssessment:
    """Create a representative risk assessment."""
    return RiskAssessment(
        finding_id=finding.finding_id,
        base_severity=RiskLevel.HIGH,
        contextual_risk=risk_level,
        context=RiskContext(
            security_requirement=finding.security_requirement,
        ),
        risk_score=75.0,
        factors=[],
        explanation=(
            f"{finding.finding_id} evaluated as "
            f"{risk_level.value} risk."
        ),
        evaluated_at="2026-09-27T00:00:00+00:00",
    )


def build_policy(
    *,
    rules: list[PolicyRule] | None = None,
    exceptions: list[PolicyException] | None = None,
    fail_on_tool_error: bool = False,
    fail_on_regression_failure: bool = True,
) -> PolicyConfig:
    """Create a representative policy configuration."""
    return PolicyConfig(
        policy_id="default-security-gate",
        version="1.0",
        rules=rules or [],
        exceptions=exceptions or [],
        fail_on_tool_error=fail_on_tool_error,
        fail_on_regression_failure=fail_on_regression_failure,
    )


def test_high_severity_block_rule_blocks_release() -> None:
    """Verify a blocking severity rule produces BLOCK."""
    finding = build_finding(severity=Severity.HIGH)
    assessment = build_assessment(finding)

    policy = build_policy(
        rules=[
            PolicyRule(
                rule_id="BLOCK-HIGH",
                name="Block high findings",
                description="High severity findings block release.",
                severity="high",
                action=PolicyAction.BLOCK,
            )
        ]
    )

    result = PolicyEngine().evaluate(
        [finding],
        [assessment],
        policy,
    )

    assert result.decision == PolicyDecision.BLOCK
    assert result.blocking_findings == ["SF-0001"]
    assert "BLOCK-HIGH" in result.triggered_rules


def test_medium_severity_review_rule_requires_review() -> None:
    """Verify a review rule produces REVIEW."""
    finding = build_finding(severity=Severity.MEDIUM)
    assessment = build_assessment(
        finding,
        risk_level=RiskLevel.MEDIUM,
    )

    policy = build_policy(
        rules=[
            PolicyRule(
                rule_id="REVIEW-MEDIUM",
                name="Review medium findings",
                description="Medium findings require review.",
                severity="medium",
                action=PolicyAction.REVIEW,
            )
        ]
    )

    result = PolicyEngine().evaluate(
        [finding],
        [assessment],
        policy,
    )

    assert result.decision == PolicyDecision.REVIEW
    assert result.review_findings == ["SF-0001"]


def test_pass_rule_allows_finding() -> None:
    """Verify an explicit pass rule produces PASS."""
    finding = build_finding(severity=Severity.LOW)
    assessment = build_assessment(
        finding,
        risk_level=RiskLevel.LOW,
    )

    policy = build_policy(
        rules=[
            PolicyRule(
                rule_id="PASS-LOW",
                name="Pass low findings",
                description="Low findings are permitted.",
                severity="low",
                action=PolicyAction.PASS,
            )
        ]
    )

    result = PolicyEngine().evaluate(
        [finding],
        [assessment],
        policy,
    )

    assert result.decision == PolicyDecision.PASS
    assert result.passed_findings == ["SF-0001"]


def test_no_matching_rule_requires_review() -> None:
    """Verify unmatched findings are not silently passed."""
    finding = build_finding(severity=Severity.HIGH)
    assessment = build_assessment(finding)

    policy = build_policy(
        rules=[
            PolicyRule(
                rule_id="BLOCK-CRITICAL",
                name="Block critical findings",
                description="Critical findings block release.",
                severity="critical",
                action=PolicyAction.BLOCK,
            )
        ]
    )

    result = PolicyEngine().evaluate(
        [finding],
        [assessment],
        policy,
    )

    assert result.decision == PolicyDecision.REVIEW
    assert result.review_findings == ["SF-0001"]
    assert any(
        "No explicit policy rule matched" in reason
        for reason in result.reasons
    )


def test_block_takes_precedence_over_review() -> None:
    """Verify the strongest decision wins across findings."""
    high_finding = build_finding(
        finding_id="SF-0001",
        severity=Severity.HIGH,
    )
    medium_finding = build_finding(
        finding_id="SF-0002",
        severity=Severity.MEDIUM,
    )

    high_assessment = build_assessment(
        high_finding,
        risk_level=RiskLevel.HIGH,
    )
    medium_assessment = build_assessment(
        medium_finding,
        risk_level=RiskLevel.MEDIUM,
    )

    policy = build_policy(
        rules=[
            PolicyRule(
                rule_id="BLOCK-HIGH",
                name="Block high findings",
                description="High findings block release.",
                severity="high",
                action=PolicyAction.BLOCK,
            ),
            PolicyRule(
                rule_id="REVIEW-MEDIUM",
                name="Review medium findings",
                description="Medium findings require review.",
                severity="medium",
                action=PolicyAction.REVIEW,
            ),
        ]
    )

    result = PolicyEngine().evaluate(
        [high_finding, medium_finding],
        [high_assessment, medium_assessment],
        policy,
    )

    assert result.decision == PolicyDecision.BLOCK
    assert result.blocking_findings == ["SF-0001"]
    assert result.review_findings == ["SF-0002"]


def test_finding_exception_is_applied() -> None:
    """Verify a finding-specific exception prevents policy enforcement."""
    finding = build_finding(severity=Severity.HIGH)
    assessment = build_assessment(finding)

    policy = build_policy(
        rules=[
            PolicyRule(
                rule_id="BLOCK-HIGH",
                name="Block high findings",
                description="High findings block release.",
                severity="high",
                action=PolicyAction.BLOCK,
            )
        ],
        exceptions=[
            PolicyException(
                exception_id="EX-0001",
                finding_id="SF-0001",
                reason="Temporary compensating control is active.",
                approved_by="security-team",
                compensating_control="Additional authorization monitoring.",
            )
        ],
    )

    result = PolicyEngine().evaluate(
        [finding],
        [assessment],
        policy,
    )

    assert result.decision == PolicyDecision.PASS
    assert result.blocking_findings == []
    assert result.exceptions_applied == ["EX-0001"]
    assert result.passed_findings == ["SF-0001"]


def test_requirement_exception_is_applied() -> None:
    """Verify a requirement-based exception can apply."""
    finding = build_finding(severity=Severity.HIGH)
    assessment = build_assessment(finding)

    policy = build_policy(
        rules=[
            PolicyRule(
                rule_id="BLOCK-HIGH",
                name="Block high findings",
                description="High findings block release.",
                severity="high",
                action=PolicyAction.BLOCK,
            )
        ],
        exceptions=[
            PolicyException(
                exception_id="EX-REQ-001",
                requirement_id="SF-AUTHZ-001",
                reason="Temporary approved exception.",
            )
        ],
    )

    result = PolicyEngine().evaluate(
        [finding],
        [assessment],
        policy,
    )

    assert result.decision == PolicyDecision.PASS
    assert result.exceptions_applied == ["EX-REQ-001"]


def test_disabled_exception_does_not_apply() -> None:
    """Verify disabled exceptions do not bypass policy."""
    finding = build_finding(severity=Severity.HIGH)
    assessment = build_assessment(finding)

    policy = build_policy(
        rules=[
            PolicyRule(
                rule_id="BLOCK-HIGH",
                name="Block high findings",
                description="High findings block release.",
                severity="high",
                action=PolicyAction.BLOCK,
            )
        ],
        exceptions=[
            PolicyException(
                exception_id="EX-DISABLED",
                finding_id="SF-0001",
                reason="This exception is disabled.",
                enabled=False,
            )
        ],
    )

    result = PolicyEngine().evaluate(
        [finding],
        [assessment],
        policy,
    )

    assert result.decision == PolicyDecision.BLOCK
    assert result.exceptions_applied == []


def test_failed_regression_blocks_when_configured() -> None:
    """Verify regression failures can block the release."""
    finding = build_finding(severity=Severity.LOW)
    assessment = build_assessment(
        finding,
        risk_level=RiskLevel.LOW,
    )

    policy = build_policy(
        rules=[
            PolicyRule(
                rule_id="PASS-LOW",
                name="Pass low findings",
                description="Low findings are permitted.",
                severity="low",
                action=PolicyAction.PASS,
            )
        ],
        fail_on_regression_failure=True,
    )

    result = PolicyEngine().evaluate(
        [finding],
        [assessment],
        policy,
        failed_regressions=["BOLA-001"],
    )

    assert result.decision == PolicyDecision.BLOCK
    assert any(
        "BOLA-001" in reason
        for reason in result.reasons
    )


def test_failed_regression_requires_review_when_not_blocking() -> None:
    """Verify configurable regression handling."""
    finding = build_finding(severity=Severity.LOW)
    assessment = build_assessment(
        finding,
        risk_level=RiskLevel.LOW,
    )

    policy = build_policy(
        rules=[
            PolicyRule(
                rule_id="PASS-LOW",
                name="Pass low findings",
                description="Low findings are permitted.",
                severity="low",
                action=PolicyAction.PASS,
            )
        ],
        fail_on_regression_failure=False,
    )

    result = PolicyEngine().evaluate(
        [finding],
        [assessment],
        policy,
        failed_regressions=["SQLI-001"],
    )

    assert result.decision == PolicyDecision.REVIEW


def test_tool_error_requires_review_by_default() -> None:
    """Verify tool errors require review under the default policy."""
    finding = build_finding(severity=Severity.LOW)
    assessment = build_assessment(
        finding,
        risk_level=RiskLevel.LOW,
    )

    policy = build_policy(
        rules=[
            PolicyRule(
                rule_id="PASS-LOW",
                name="Pass low findings",
                description="Low findings are permitted.",
                severity="low",
                action=PolicyAction.PASS,
            )
        ]
    )

    result = PolicyEngine().evaluate(
        [finding],
        [assessment],
        policy,
        tool_errors=1,
    )

    assert result.decision == PolicyDecision.REVIEW
    assert any(
        "tool execution error" in reason
        for reason in result.reasons
    )


def test_tool_error_can_block_when_configured() -> None:
    """Verify tool failure policy can be configured to block."""
    finding = build_finding(severity=Severity.LOW)
    assessment = build_assessment(
        finding,
        risk_level=RiskLevel.LOW,
    )

    policy = build_policy(
        rules=[
            PolicyRule(
                rule_id="PASS-LOW",
                name="Pass low findings",
                description="Low findings are permitted.",
                severity="low",
                action=PolicyAction.PASS,
            )
        ],
        fail_on_tool_error=True,
    )

    result = PolicyEngine().evaluate(
        [finding],
        [assessment],
        policy,
        tool_errors=1,
    )

    assert result.decision == PolicyDecision.BLOCK


def test_disabled_rule_does_not_trigger() -> None:
    """Verify disabled policy rules are ignored."""
    finding = build_finding(severity=Severity.HIGH)
    assessment = build_assessment(finding)

    policy = build_policy(
        rules=[
            PolicyRule(
                rule_id="BLOCK-HIGH",
                name="Disabled high block",
                description="This rule should not execute.",
                severity="high",
                action=PolicyAction.BLOCK,
                enabled=False,
            )
        ]
    )

    result = PolicyEngine().evaluate(
        [finding],
        [assessment],
        policy,
    )

    assert result.decision == PolicyDecision.REVIEW
    assert result.triggered_rules == []


def test_risk_level_rule_can_trigger_without_matching_severity() -> None:
    """Verify policies can match contextual risk independently."""
    finding = build_finding(severity=Severity.MEDIUM)
    assessment = build_assessment(
        finding,
        risk_level=RiskLevel.HIGH,
    )

    policy = build_policy(
        rules=[
            PolicyRule(
                rule_id="BLOCK-HIGH-RISK",
                name="Block high contextual risk",
                description="High contextual risk blocks release.",
                risk_level="high",
                action=PolicyAction.BLOCK,
            )
        ]
    )

    result = PolicyEngine().evaluate(
        [finding],
        [assessment],
        policy,
    )

    assert result.decision == PolicyDecision.BLOCK
    assert result.blocking_findings == ["SF-0001"]


def test_policy_result_preserves_policy_identity() -> None:
    """Verify policy metadata is preserved in evaluation results."""
    finding = build_finding(severity=Severity.LOW)
    assessment = build_assessment(
        finding,
        risk_level=RiskLevel.LOW,
    )

    policy = build_policy(
        rules=[
            PolicyRule(
                rule_id="PASS-LOW",
                name="Pass low findings",
                description="Low findings are permitted.",
                severity="low",
                action=PolicyAction.PASS,
            )
        ]
    )

    result = PolicyEngine().evaluate(
        [finding],
        [assessment],
        policy,
    )

    assert result.policy_id == "default-security-gate"
    assert result.policy_version == "1.0"
