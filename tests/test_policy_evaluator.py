"""Tests for the SecureForge policy evaluator."""

from secureforge.core.findings import Finding, Severity
from secureforge.core.policy import (
PolicyAction,
PolicyConfig,
PolicyException,
PolicyRule,
)
from secureforge.core.policy.evaluator import PolicyEvaluator
from secureforge.core.risk import (
RiskContext,
RiskLevel,
RiskAssessment,
)

def build_finding(
finding_id: str = "SF-001",
*,
severity: Severity = Severity.HIGH,
security_requirement: str | None = "SF-AUTHZ-001",
) -> Finding:
"""Create a representative finding."""
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
security_requirement=security_requirement,
severity=severity,
description="Authorization bypass was confirmed.",
impact="Users may access unauthorized objects.",
remediation="Enforce object-level authorization.",
)

def build_assessment(
finding_id: str = "SF-001",
*,
risk_level: RiskLevel = RiskLevel.HIGH,
) -> RiskAssessment:
"""Create a representative risk assessment."""
return RiskAssessment(
finding_id=finding_id,
base_severity=RiskLevel.HIGH,
contextual_risk=risk_level,
context=RiskContext(
security_requirement="SF-AUTHZ-001"
),
risk_score=75.0,
factors=[],
explanation="Test risk assessment.",
evaluated_at="2026-09-27T00:00:00+00:00",
)

def build_rule(
rule_id: str = "BLOCK-HIGH",
*,
severity: str | None = "high",
risk_level: str | None = None,
action: PolicyAction = PolicyAction.BLOCK,
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
) -> PolicyConfig:
"""Create a representative policy configuration."""
return PolicyConfig(
policy_id="test-policy",
version="1.0",
rules=rules or [],
exceptions=exceptions or [],
)

def test_rule_matches_severity() -> None:
"""Verify a severity-based rule matches correctly."""
evaluator = PolicyEvaluator()

```
finding = build_finding(
    severity=Severity.HIGH
)
assessment = build_assessment()

rule = build_rule(
    severity="high"
)

assert evaluator.rule_matches(
    finding,
    assessment,
    rule,
)
```

def test_rule_does_not_match_different_severity() -> None:
"""Verify mismatched severity prevents a rule match."""
evaluator = PolicyEvaluator()

```
finding = build_finding(
    severity=Severity.MEDIUM
)
assessment = build_assessment()

rule = build_rule(
    severity="high"
)

assert not evaluator.rule_matches(
    finding,
    assessment,
    rule,
)
```

def test_rule_matches_risk_level() -> None:
"""Verify a contextual risk rule matches correctly."""
evaluator = PolicyEvaluator()

```
finding = build_finding()
assessment = build_assessment(
    risk_level=RiskLevel.CRITICAL
)

rule = build_rule(
    severity=None,
    risk_level="critical",
)

assert evaluator.rule_matches(
    finding,
    assessment,
    rule,
)
```

def test_rule_does_not_match_different_risk_level() -> None:
"""Verify mismatched risk level prevents a rule match."""
evaluator = PolicyEvaluator()

```
finding = build_finding()
assessment = build_assessment(
    risk_level=RiskLevel.MEDIUM
)

rule = build_rule(
    severity=None,
    risk_level="critical",
)

assert not evaluator.rule_matches(
    finding,
    assessment,
    rule,
)
```

def test_rule_matches_when_no_conditions_are_set() -> None:
"""Verify an unconditional rule matches."""
evaluator = PolicyEvaluator()

```
finding = build_finding()
assessment = build_assessment()

rule = build_rule(
    severity=None,
    risk_level=None,
)

assert evaluator.rule_matches(
    finding,
    assessment,
    rule,
)
```

def test_rule_matching_is_case_insensitive() -> None:
"""Verify severity and risk values are normalized."""
evaluator = PolicyEvaluator()

```
finding = build_finding(
    severity=Severity.HIGH
)
assessment = build_assessment(
    risk_level=RiskLevel.HIGH
)

rule = build_rule(
    severity="HIGH",
    risk_level="HIGH",
)

assert evaluator.rule_matches(
    finding,
    assessment,
    rule,
)
```

def test_match_rule_returns_matching_rule() -> None:
"""Verify matching rules are selected."""
evaluator = PolicyEvaluator()

```
finding = build_finding()
assessment = build_assessment()

rules = [
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

matched = evaluator.match_rule(
    finding,
    assessment,
    rules,
)

assert matched is not None
assert matched.rule_id == "BLOCK-HIGH"
```

def test_match_rule_ignores_disabled_rules() -> None:
"""Verify disabled rules cannot trigger."""
evaluator = PolicyEvaluator()

```
finding = build_finding()
assessment = build_assessment()

rules = [
    build_rule(
        "DISABLED-BLOCK",
        severity="high",
        action=PolicyAction.BLOCK,
        enabled=False,
    ),
    build_rule(
        "REVIEW-HIGH",
        severity="high",
        action=PolicyAction.REVIEW,
    ),
]

matched = evaluator.match_rule(
    finding,
    assessment,
    rules,
)

assert matched is not None
assert matched.rule_id == "REVIEW-HIGH"
```

def test_match_rule_prefers_block_over_review() -> None:
"""Verify higher-priority actions win when rules overlap."""
evaluator = PolicyEvaluator()

```
finding = build_finding()
assessment = build_assessment()

rules = [
    build_rule(
        "REVIEW-HIGH",
        severity="high",
        action=PolicyAction.REVIEW,
    ),
    build_rule(
        "BLOCK-HIGH",
        severity="high",
        action=PolicyAction.BLOCK,
    ),
]

matched = evaluator.match_rule(
    finding,
    assessment,
    rules,
)

assert matched is not None
assert matched.rule_id == "BLOCK-HIGH"
```

def test_match_rule_prefers_review_over_pass() -> None:
"""Verify review outranks pass."""
evaluator = PolicyEvaluator()

```
finding = build_finding()
assessment = build_assessment()

rules = [
    build_rule(
        "PASS-HIGH",
        severity="high",
        action=PolicyAction.PASS,
    ),
    build_rule(
        "REVIEW-HIGH",
        severity="high",
        action=PolicyAction.REVIEW,
    ),
]

matched = evaluator.match_rule(
    finding,
    assessment,
    rules,
)

assert matched is not None
assert matched.rule_id == "REVIEW-HIGH"
```

def test_match_rule_returns_none_when_nothing_matches() -> None:
"""Verify unmatched findings return no rule."""
evaluator = PolicyEvaluator()

```
finding = build_finding(
    severity=Severity.LOW
)
assessment = build_assessment(
    risk_level=RiskLevel.LOW
)

rules = [
    build_rule(
        severity="critical"
    ),
    build_rule(
        "HIGH-RULE",
        severity="high",
    ),
]

matched = evaluator.match_rule(
    finding,
    assessment,
    rules,
)

assert matched is None
```

def test_exception_matches_finding_id() -> None:
"""Verify an exception can target a specific finding."""
evaluator = PolicyEvaluator()

```
finding = build_finding(
    finding_id="SF-EXCEPTION-001"
)

exception = PolicyException(
    exception_id="EXC-001",
    finding_id="SF-EXCEPTION-001",
    reason="Temporary accepted risk.",
)

policy = build_policy(
    exceptions=[exception]
)

assert evaluator.exception_applies(
    finding,
    policy,
)
```

def test_exception_matches_requirement_id() -> None:
"""Verify an exception can target a requirement."""
evaluator = PolicyEvaluator()

```
finding = build_finding(
    security_requirement="SF-AUTHZ-001"
)

exception = PolicyException(
    exception_id="EXC-001",
    requirement_id="SF-AUTHZ-001",
    reason="Temporary accepted risk.",
)

policy = build_policy(
    exceptions=[exception]
)

assert evaluator.exception_applies(
    finding,
    policy,
)
```

def test_exception_does_not_match_unrelated_finding() -> None:
"""Verify unrelated exceptions do not apply."""
evaluator = PolicyEvaluator()

```
finding = build_finding(
    finding_id="SF-001"
)

exception = PolicyException(
    exception_id="EXC-001",
    finding_id="SF-999",
    reason="Temporary accepted risk.",
)

policy = build_policy(
    exceptions=[exception]
)

assert not evaluator.exception_applies(
    finding,
    policy,
)
```

def test_disabled_exception_does_not_apply() -> None:
"""Verify disabled exceptions are ignored."""
evaluator = PolicyEvaluator()

```
finding = build_finding(
    finding_id="SF-001"
)

exception = PolicyException(
    exception_id="EXC-001",
    finding_id="SF-001",
    reason="Temporary accepted risk.",
    enabled=False,
)

policy = build_policy(
    exceptions=[exception]
)

assert not evaluator.exception_applies(
    finding,
    policy,
)
```

def test_find_exception_returns_matching_exception() -> None:
"""Verify the matching exception object is returned."""
evaluator = PolicyEvaluator()

```
finding = build_finding(
    finding_id="SF-001"
)

exception = PolicyException(
    exception_id="EXC-001",
    finding_id="SF-001",
    reason="Temporary accepted risk.",
)

policy = build_policy(
    exceptions=[exception]
)

result = evaluator.find_exception(
    finding,
    policy,
)

assert result is not None
assert result.exception_id == "EXC-001"
```

def test_find_exception_returns_none_when_unmatched() -> None:
"""Verify no exception returns None."""
evaluator = PolicyEvaluator()

```
finding = build_finding(
    finding_id="SF-001"
)

policy = build_policy()

assert evaluator.find_exception(
    finding,
    policy,
) is None
```

def test_action_priority() -> None:
"""Verify policy action priorities."""
evaluator = PolicyEvaluator()

```
assert evaluator.action_priority(
    PolicyAction.PASS
) == 0

assert evaluator.action_priority(
    PolicyAction.REVIEW
) == 1

assert evaluator.action_priority(
    PolicyAction.BLOCK
) == 2
```

def test_highest_action_returns_block() -> None:
"""Verify block is the highest action."""
evaluator = PolicyEvaluator()

```
result = evaluator.highest_action(
    [
        PolicyAction.PASS,
        PolicyAction.REVIEW,
        PolicyAction.BLOCK,
    ]
)

assert result == PolicyAction.BLOCK
```

def test_highest_action_returns_review() -> None:
"""Verify review outranks pass."""
evaluator = PolicyEvaluator()

```
result = evaluator.highest_action(
    [
        PolicyAction.PASS,
        PolicyAction.REVIEW,
    ]
)

assert result == PolicyAction.REVIEW
```

def test_highest_action_returns_pass_for_empty_list() -> None:
"""Verify an empty action set defaults to pass."""
evaluator = PolicyEvaluator()

```
assert evaluator.highest_action([]) == PolicyAction.PASS
```
