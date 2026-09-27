"""Tests for the repository default SecureForge policy."""

from pathlib import Path

from secureforge.core.findings import (
Finding,
Severity,
)
from secureforge.core.policy import (
PolicyAction,
PolicyDecision,
PolicyLoader,
PolicyEngine,
PolicyEvaluator,
)
from secureforge.core.risk import (
RiskAssessment,
RiskContext,
RiskLevel,
)

REPOSITORY_ROOT = Path(**file**).resolve().parents[1]
POLICY_FILE = (
REPOSITORY_ROOT
/ "policies"
/ "default.yaml"
)

def build_finding(
finding_id: str,
severity: Severity,
) -> Finding:
"""Create a representative finding for policy testing."""
return Finding(
finding_id=finding_id,
title=f"Test {severity.value} finding",
source="test",
application="SecureCommerce",
asset="securecommerce-api",
severity=severity,
description="Controlled test finding.",
impact="Controlled test impact.",
remediation="Controlled test remediation.",
)

def build_assessment(
finding_id: str,
risk_level: RiskLevel,
) -> RiskAssessment:
"""Create a representative risk assessment."""
return RiskAssessment(
finding_id=finding_id,
base_severity=risk_level,
contextual_risk=risk_level,
context=RiskContext(),
risk_score=50.0,
explanation="Controlled test assessment.",
evaluated_at="2026-01-01T00:00:00+00:00",
)

def load_default_policy():
"""Load the repository default policy."""
loader = PolicyLoader()

```
return loader.load_file(
    POLICY_FILE
)
```

def test_default_policy_file_exists() -> None:
"""Verify the default policy file exists."""
assert POLICY_FILE.exists()
assert POLICY_FILE.is_file()

def test_default_policy_loads_successfully() -> None:
"""Verify the default policy YAML is valid."""
policy = load_default_policy()

```
assert policy.policy_id == "secureforge-default"
assert policy.version == "1.0"
```

def test_default_policy_has_expected_rules() -> None:
"""Verify the expected severity rules are configured."""
policy = load_default_policy()

```
rule_ids = {
    rule.rule_id
    for rule in policy.rules
}

assert rule_ids == {
    "BLOCK-CRITICAL",
    "BLOCK-HIGH",
    "REVIEW-MEDIUM",
    "PASS-LOW",
    "PASS-INFO",
}
```

def test_default_policy_blocks_critical() -> None:
"""Verify critical findings trigger BLOCK."""
policy = load_default_policy()

```
rule = next(
    rule
    for rule in policy.rules
    if rule.rule_id == "BLOCK-CRITICAL"
)

assert rule.severity == "critical"
assert rule.action == PolicyAction.BLOCK
assert rule.enabled is True
```

def test_default_policy_blocks_high() -> None:
"""Verify high findings trigger BLOCK."""
policy = load_default_policy()

```
rule = next(
    rule
    for rule in policy.rules
    if rule.rule_id == "BLOCK-HIGH"
)

assert rule.severity == "high"
assert rule.action == PolicyAction.BLOCK
assert rule.enabled is True
```

def test_default_policy_reviews_medium() -> None:
"""Verify medium findings trigger REVIEW."""
policy = load_default_policy()

```
rule = next(
    rule
    for rule in policy.rules
    if rule.rule_id == "REVIEW-MEDIUM"
)

assert rule.severity == "medium"
assert rule.action == PolicyAction.REVIEW
assert rule.enabled is True
```

def test_default_policy_passes_low() -> None:
"""Verify low findings trigger PASS."""
policy = load_default_policy()

```
rule = next(
    rule
    for rule in policy.rules
    if rule.rule_id == "PASS-LOW"
)

assert rule.severity == "low"
assert rule.action == PolicyAction.PASS
assert rule.enabled is True
```

def test_default_policy_passes_info() -> None:
"""Verify informational findings trigger PASS."""
policy = load_default_policy()

```
rule = next(
    rule
    for rule in policy.rules
    if rule.rule_id == "PASS-INFO"
)

assert rule.severity == "info"
assert rule.action == PolicyAction.PASS
assert rule.enabled is True
```

def test_default_policy_has_no_exceptions() -> None:
"""Verify the baseline policy has no implicit exceptions."""
policy = load_default_policy()

```
assert policy.exceptions == []
```

def test_default_policy_fails_on_regression_failure() -> None:
"""Verify failed regressions are configured to block."""
policy = load_default_policy()

```
assert policy.fail_on_regression_failure is True
```

def test_default_policy_allows_tool_errors_to_require_review() -> None:
"""Verify tool errors do not automatically block by configuration."""
policy = load_default_policy()

```
assert policy.fail_on_tool_error is False
```

def test_default_policy_blocks_critical_finding() -> None:
"""Verify the loaded policy engine blocks a critical finding."""
policy = load_default_policy()

```
finding = build_finding(
    "SF-CRITICAL-001",
    Severity.CRITICAL,
)

assessment = build_assessment(
    finding.finding_id,
    RiskLevel.CRITICAL,
)

evaluation = PolicyEngine().evaluate(
    [finding],
    [assessment],
    policy,
)

assert evaluation.decision == PolicyDecision.BLOCK
assert evaluation.blocking_findings == [
    finding.finding_id
]
```

def test_default_policy_blocks_high_finding() -> None:
"""Verify the loaded policy engine blocks a high finding."""
policy = load_default_policy()

```
finding = build_finding(
    "SF-HIGH-001",
    Severity.HIGH,
)

assessment = build_assessment(
    finding.finding_id,
    RiskLevel.HIGH,
)

evaluation = PolicyEngine().evaluate(
    [finding],
    [assessment],
    policy,
)

assert evaluation.decision == PolicyDecision.BLOCK
assert evaluation.blocking_findings == [
    finding.finding_id
]
```

def test_default_policy_reviews_medium_finding() -> None:
"""Verify the loaded policy engine reviews a medium finding."""
policy = load_default_policy()

```
finding = build_finding(
    "SF-MEDIUM-001",
    Severity.MEDIUM,
)

assessment = build_assessment(
    finding.finding_id,
    RiskLevel.MEDIUM,
)

evaluation = PolicyEngine().evaluate(
    [finding],
    [assessment],
    policy,
)

assert evaluation.decision == PolicyDecision.REVIEW
assert evaluation.review_findings == [
    finding.finding_id
]
```

def test_default_policy_passes_low_finding() -> None:
"""Verify the loaded policy engine passes a low finding."""
policy = load_default_policy()

```
finding = build_finding(
    "SF-LOW-001",
    Severity.LOW,
)

assessment = build_assessment(
    finding.finding_id,
    RiskLevel.LOW,
)

evaluation = PolicyEngine().evaluate(
    [finding],
    [assessment],
    policy,
)

assert evaluation.decision == PolicyDecision.PASS
assert evaluation.passed_findings == [
    finding.finding_id
]
```

def test_default_policy_passes_info_finding() -> None:
"""Verify the loaded policy engine passes an informational finding."""
policy = load_default_policy()

```
finding = build_finding(
    "SF-INFO-001",
    Severity.INFO,
)

assessment = build_assessment(
    finding.finding_id,
    RiskLevel.INFO,
)

evaluation = PolicyEngine().evaluate(
    [finding],
    [assessment],
    policy,
)

assert evaluation.decision == PolicyDecision.PASS
assert evaluation.passed_findings == [
    finding.finding_id
]
```

def test_default_policy_uses_highest_decision_for_multiple_findings() -> None:
"""Verify BLOCK outranks REVIEW and PASS."""
policy = load_default_policy()

```
critical = build_finding(
    "SF-CRITICAL-001",
    Severity.CRITICAL,
)

medium = build_finding(
    "SF-MEDIUM-001",
    Severity.MEDIUM,
)

low = build_finding(
    "SF-LOW-001",
    Severity.LOW,
)

assessments = [
    build_assessment(
        critical.finding_id,
        RiskLevel.CRITICAL,
    ),
    build_assessment(
        medium.finding_id,
        RiskLevel.MEDIUM,
    ),
    build_assessment(
        low.finding_id,
        RiskLevel.LOW,
    ),
]

evaluation = PolicyEngine().evaluate(
    [critical, medium, low],
    assessments,
    policy,
)

assert evaluation.decision == PolicyDecision.BLOCK

assert critical.finding_id in (
    evaluation.blocking_findings
)

assert medium.finding_id in (
    evaluation.review_findings
)

assert low.finding_id in (
    evaluation.passed_findings
)
```

def test_default_policy_metadata_is_present() -> None:
"""Verify the policy carries useful operational metadata."""
policy = load_default_policy()

```
assert policy.metadata["intended_environment"] == "lab"
assert policy.metadata["policy_owner"] == "SecureForge"
assert (
    policy.metadata["review_required_for_exceptions"]
    is True
)
```

def test_default_policy_rules_are_unique() -> None:
"""Verify policy rule identifiers are unique."""
policy = load_default_policy()

```
rule_ids = [
    rule.rule_id
    for rule in policy.rules
]

assert len(rule_ids) == len(
    set(rule_ids)
)
```

def test_default_policy_evaluator_matches_expected_actions() -> None:
"""Verify the evaluator resolves the configured actions."""
policy = load_default_policy()
evaluator = PolicyEvaluator()

```
test_cases = [
    (Severity.CRITICAL, PolicyAction.BLOCK),
    (Severity.HIGH, PolicyAction.BLOCK),
    (Severity.MEDIUM, PolicyAction.REVIEW),
    (Severity.LOW, PolicyAction.PASS),
    (Severity.INFO, PolicyAction.PASS),
]

for index, (severity, expected_action) in enumerate(
    test_cases,
    start=1,
):
    finding = build_finding(
        f"SF-POLICY-{index:03d}",
        severity,
    )

    assessment = build_assessment(
        finding.finding_id,
        RiskLevel(severity.value),
    )

    rule = evaluator.match_rule(
        finding,
        assessment,
        policy.rules,
    )

    assert rule is not None
    assert rule.action == expected_action
```
