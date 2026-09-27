"""Tests for the SecureForge policy evaluation engine."""

from secureforge.core.findings import Finding, Severity
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
finding_id: str = "SF-001",
*,
severity: Severity = Severity.HIGH,
requirement: str | None = "SF-AUTHZ-001",
) -> Finding:
"""Create a representative security finding."""
return Finding(
finding_id=finding_id,
title="Broken Object Level Authorization",
source="dast",
application="SecureCommerce",
asset="securecommerce-api",
endpoint="/api/orders/123",
parameter="id",
cwe="CWE-639",
owasp="API1",
security_requirement=requirement,
severity=severity,
description="Authorization bypass was confirmed.",
impact="Unauthorized objects may be accessed.",
remediation="Enforce object-level authorization.",
)

def build_assessment(
finding_id: str = "SF-001",
*,
risk: RiskLevel = RiskLevel.HIGH,
) -> RiskAssessment:
"""Create a representative risk assessment."""
return RiskAssessment(
finding_id=finding_id,
base_severity=RiskLevel.HIGH,
contextual_risk=risk,
context=RiskContext(
security_requirement="SF-AUTHZ-001"
),
risk_score=75.0,
factors=[],
explanation="Test risk assessment.",
evaluated_at="2026-09-27T00:00:00+00:00",
)

def build_rule(
rule_id: str,
*,
severity: str | None = None,
risk_level: str | None = None,
action: PolicyAction = PolicyAction.PASS,
enabled: bool = True,
) -> PolicyRule:
"""Create a representative policy rule."""
return PolicyRule(
rule_id=rule_id,
name=rule_id,
description="Test policy rule.",
severity=severity,
risk_level=risk_level,
action=action,
enabled=enabled,
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
policy_id="test-policy",
version="1.0",
rules=rules or [],
exceptions=exceptions or [],
fail_on_tool_error=fail_on_tool_error,
fail_on_regression_failure=fail_on_regression_failure,
)

def test_engine_blocks_high_finding() -> None:
"""Verify a blocking rule produces a block decision."""
finding = build_finding(
severity=Severity.HIGH
)

```
assessment = build_assessment()

policy = build_policy(
    rules=[
        build_rule(
            "BLOCK-HIGH",
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
assert result.blocking_findings == [
    "SF-001"
]
assert result.triggered_rules == [
    "BLOCK-HIGH"
]
```

def test_engine_reviews_medium_finding() -> None:
"""Verify a review rule produces a review decision."""
finding = build_finding(
severity=Severity.MEDIUM
)

```
assessment = build_assessment(
    risk=RiskLevel.MEDIUM
)

policy = build_policy(
    rules=[
        build_rule(
            "REVIEW-MEDIUM",
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
assert result.review_findings == [
    "SF-001"
]
```

def test_engine_passes_finding() -> None:
"""Verify an explicit pass rule produces a pass decision."""
finding = build_finding(
severity=Severity.LOW
)

```
assessment = build_assessment(
    risk=RiskLevel.LOW
)

policy = build_policy(
    rules=[
        build_rule(
            "PASS-LOW",
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
assert result.passed_findings == [
    "SF-001"
]
```

def test_engine_requires_review_when_no_rule_matches() -> None:
"""Verify unmatched findings require review."""
finding = build_finding(
severity=Severity.MEDIUM
)

```
assessment = build_assessment(
    risk=RiskLevel.MEDIUM
)

policy = build_policy(
    rules=[
        build_rule(
            "BLOCK-CRITICAL",
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
assert result.review_findings == [
    "SF-001"
]
assert result.triggered_rules == []
```

def test_engine_requires_review_when_assessment_is_missing() -> None:
"""Verify findings without risk assessments require review."""
finding = build_finding()

```
policy = build_policy(
    rules=[
        build_rule(
            "BLOCK-HIGH",
            severity="high",
            action=PolicyAction.BLOCK,
        )
    ]
)

result = PolicyEngine().evaluate(
    [finding],
    [],
    policy,
)

assert result.decision == PolicyDecision.REVIEW
assert result.review_findings == [
    "SF-001"
]
assert any(
    "No risk assessment" in reason
    for reason in result.reasons
)
```

def test_engine_applies_finding_exception() -> None:
"""Verify an exception bypasses the matching blocking rule."""
finding = build_finding()

```
assessment = build_assessment()

policy = build_policy(
    rules=[
        build_rule(
            "BLOCK-HIGH",
            severity="high",
            action=PolicyAction.BLOCK,
        )
    ],
    exceptions=[
        PolicyException(
            exception_id="EXC-001",
            finding_id="SF-001",
            reason="Temporary accepted risk.",
        )
    ],
)

result = PolicyEngine().evaluate(
    [finding],
    [assessment],
    policy,
)

assert result.decision == PolicyDecision.PASS
assert result.exceptions_applied == [
    "EXC-001"
]
assert result.blocking_findings == []
```

def test_engine_applies_requirement_exception() -> None:
"""Verify a requirement-level exception is applied."""
finding = build_finding(
requirement="SF-AUTHZ-001"
)

```
assessment = build_assessment()

policy = build_policy(
    rules=[
        build_rule(
            "BLOCK-HIGH",
            severity="high",
            action=PolicyAction.BLOCK,
        )
    ],
    exceptions=[
        PolicyException(
            exception_id="EXC-AUTHZ",
            requirement_id="SF-AUTHZ-001",
            reason="Temporary exception.",
        )
    ],
)

result = PolicyEngine().evaluate(
    [finding],
    [assessment],
    policy,
)

assert result.decision == PolicyDecision.PASS
assert result.exceptions_applied == [
    "EXC-AUTHZ"
]
```

def test_engine_blocks_on_failed_regression() -> None:
"""Verify failed regression tests block by default."""
policy = build_policy()

```
result = PolicyEngine().evaluate(
    [],
    [],
    policy,
    failed_regressions=[
        "BOLA-001"
    ],
)

assert result.decision == PolicyDecision.BLOCK
assert any(
    "BOLA-001" in reason
    for reason in result.reasons
)
```

def test_engine_reviews_failed_regression_when_configured() -> None:
"""Verify regression failures can be configured for review."""
policy = build_policy(
fail_on_regression_failure=False
)

```
result = PolicyEngine().evaluate(
    [],
    [],
    policy,
    failed_regressions=[
        "BOLA-001"
    ],
)

assert result.decision == PolicyDecision.REVIEW
```

def test_engine_blocks_on_tool_error_when_configured() -> None:
"""Verify tool errors can block a release."""
policy = build_policy(
fail_on_tool_error=True
)

```
result = PolicyEngine().evaluate(
    [],
    [],
    policy,
    tool_errors=1,
)

assert result.decision == PolicyDecision.BLOCK
assert any(
    "tool execution error" in reason
    for reason in result.reasons
)
```

def test_engine_reviews_tool_error_by_default() -> None:
"""Verify tool errors require review by default."""
policy = build_policy()

```
result = PolicyEngine().evaluate(
    [],
    [],
    policy,
    tool_errors=1,
)

assert result.decision == PolicyDecision.REVIEW
```

def test_engine_block_takes_precedence_over_review() -> None:
"""Verify one blocking finding dominates review findings."""
blocking_finding = build_finding(
finding_id="SF-BLOCK",
severity=Severity.HIGH,
)

```
review_finding = build_finding(
    finding_id="SF-REVIEW",
    severity=Severity.MEDIUM,
)

blocking_assessment = build_assessment(
    finding_id="SF-BLOCK"
)

review_assessment = build_assessment(
    finding_id="SF-REVIEW",
    risk=RiskLevel.MEDIUM,
)

policy = build_policy(
    rules=[
        build_rule(
            "BLOCK-HIGH",
            severity="high",
            action=PolicyAction.BLOCK,
        ),
        build_rule(
            "REVIEW-MEDIUM",
            severity="medium",
            action=PolicyAction.REVIEW,
        ),
    ]
)

result = PolicyEngine().evaluate(
    [
        blocking_finding,
        review_finding,
    ],
    [
        blocking_assessment,
        review_assessment,
    ],
    policy,
)

assert result.decision == PolicyDecision.BLOCK
assert result.blocking_findings == [
    "SF-BLOCK"
]
assert result.review_findings == [
    "SF-REVIEW"
]
```

def test_engine_deduplicates_triggered_rules() -> None:
"""Verify repeated rule IDs appear only once."""
first = build_finding(
finding_id="SF-001"
)

```
second = build_finding(
    finding_id="SF-002"
)

first_assessment = build_assessment(
    finding_id="SF-001"
)

second_assessment = build_assessment(
    finding_id="SF-002"
)

policy = build_policy(
    rules=[
        build_rule(
            "BLOCK-HIGH",
            severity="high",
            action=PolicyAction.BLOCK,
        )
    ]
)

result = PolicyEngine().evaluate(
    [
        first,
        second,
    ],
    [
        first_assessment,
        second_assessment,
    ],
    policy,
)

assert result.triggered_rules == [
    "BLOCK-HIGH"
]
```

def test_engine_deduplicates_exceptions() -> None:
"""Verify repeated exception IDs appear only once."""
first = build_finding(
finding_id="SF-001"
)

```
second = build_finding(
    finding_id="SF-002"
)

first_assessment = build_assessment(
    finding_id="SF-001"
)

second_assessment = build_assessment(
    finding_id="SF-002"
)

policy = build_policy(
    exceptions=[
        PolicyException(
            exception_id="EXC-REQ",
            requirement_id="SF-AUTHZ-001",
            reason="Temporary exception.",
        )
    ]
)

result = PolicyEngine().evaluate(
    [
        first,
        second,
    ],
    [
        first_assessment,
        second_assessment,
    ],
    policy,
)

assert result.exceptions_applied == [
    "EXC-REQ"
]
```

def test_engine_records_pass_reason() -> None:
"""Verify explicit pass rules produce an explanation."""
finding = build_finding(
severity=Severity.LOW
)

```
assessment = build_assessment(
    risk=RiskLevel.LOW
)

policy = build_policy(
    rules=[
        build_rule(
            "PASS-LOW",
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

assert any(
    "passed rule PASS-LOW" in reason
    for reason in result.reasons
)
```

def test_engine_empty_input_defaults_to_pass() -> None:
"""Verify no findings and no errors produce pass."""
policy = build_policy()

```
result = PolicyEngine().evaluate(
    [],
    [],
    policy,
)

assert result.decision == PolicyDecision.PASS
assert result.reasons == [
    "No policy conditions were triggered."
]
```

def test_engine_policy_identity_is_preserved() -> None:
"""Verify policy identity appears in the evaluation."""
policy = build_policy()

```
result = PolicyEngine().evaluate(
    [],
    [],
    policy,
)

assert result.policy_id == "test-policy"
assert result.policy_version == "1.0"
```
