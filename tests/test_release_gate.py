"""Tests for the SecureForge release-gate engine."""

from secureforge.core.policy import PolicyDecision
from secureforge.core.release_gate import (
ReleaseDecision,
ReleaseGateEngine,
ReleaseGateInput,
)

def build_input(
*,
policy_decision: PolicyDecision = PolicyDecision.PASS,
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
commit_sha="abc123def456",
policy_decision=ReleaseDecision(policy_decision.value),
blocking_findings=blocking_findings or [],
review_findings=review_findings or [],
failed_regressions=failed_regressions or [],
tool_errors=tool_errors or [],
exceptions_applied=exceptions_applied or [],
)

def test_pass_policy_produces_pass() -> None:
"""Verify a clean policy result passes the release gate."""
gate_input = build_input(
policy_decision=PolicyDecision.PASS,
)

```
result = ReleaseGateEngine().evaluate(gate_input)

assert result.decision == ReleaseDecision.PASS
assert result.passed is True
assert result.requires_review is False
assert result.is_blocked is False
```

def test_review_policy_produces_review() -> None:
"""Verify policy review becomes a release review decision."""
gate_input = build_input(
policy_decision=PolicyDecision.REVIEW,
review_findings=["SF-0001"],
)

```
result = ReleaseGateEngine().evaluate(gate_input)

assert result.decision == ReleaseDecision.REVIEW
assert result.requires_review is True
assert result.review_findings == ["SF-0001"]
```

def test_block_policy_produces_block() -> None:
"""Verify a blocking policy result blocks release."""
gate_input = build_input(
policy_decision=PolicyDecision.BLOCK,
blocking_findings=["SF-0001"],
)

```
result = ReleaseGateEngine().evaluate(gate_input)

assert result.decision == ReleaseDecision.BLOCK
assert result.is_blocked is True
assert result.blocking_findings == ["SF-0001"]
```

def test_blocking_findings_force_block() -> None:
"""Verify blocking findings cannot be overridden by a PASS policy result."""
gate_input = build_input(
policy_decision=PolicyDecision.PASS,
blocking_findings=["SF-CRITICAL-001"],
)

```
result = ReleaseGateEngine().evaluate(gate_input)

assert result.decision == ReleaseDecision.BLOCK
assert result.is_blocked is True
assert any(
    "release-blocking" in reason
    for reason in result.reasons
)
```

def test_failed_regression_forces_block() -> None:
"""Verify security regression failures block the release."""
gate_input = build_input(
policy_decision=PolicyDecision.PASS,
failed_regressions=["BOLA-001"],
)

```
result = ReleaseGateEngine().evaluate(gate_input)

assert result.decision == ReleaseDecision.BLOCK
assert result.failed_regressions == ["BOLA-001"]
assert any(
    "regression" in reason.lower()
    for reason in result.reasons
)
```

def test_tool_error_requires_review() -> None:
"""Verify tool execution errors require review."""
gate_input = build_input(
policy_decision=PolicyDecision.PASS,
tool_errors=["Nmap execution failed."],
)

```
result = ReleaseGateEngine().evaluate(gate_input)

assert result.decision == ReleaseDecision.REVIEW
assert result.tool_errors == ["Nmap execution failed."]
```

def test_block_takes_precedence_over_tool_error() -> None:
"""Verify BLOCK takes precedence over REVIEW."""
gate_input = build_input(
policy_decision=PolicyDecision.PASS,
blocking_findings=["SF-0001"],
tool_errors=["Scanner failed."],
)

```
result = ReleaseGateEngine().evaluate(gate_input)

assert result.decision == ReleaseDecision.BLOCK
```

def test_block_takes_precedence_over_review_findings() -> None:
"""Verify blocking findings take precedence over review findings."""
gate_input = build_input(
policy_decision=PolicyDecision.REVIEW,
blocking_findings=["SF-0001"],
review_findings=["SF-0002"],
)

```
result = ReleaseGateEngine().evaluate(gate_input)

assert result.decision == ReleaseDecision.BLOCK
```

def test_exceptions_are_preserved() -> None:
"""Verify applied policy exceptions remain auditable."""
gate_input = build_input(
policy_decision=PolicyDecision.PASS,
exceptions_applied=["EX-0001"],
)

```
result = ReleaseGateEngine().evaluate(gate_input)

assert result.decision == ReleaseDecision.PASS
assert result.exceptions_applied == ["EX-0001"]
assert any(
    "exception" in reason.lower()
    for reason in result.reasons
)
```

def test_release_metadata_is_preserved() -> None:
"""Verify application and version information survives evaluation."""
gate_input = build_input(
policy_decision=PolicyDecision.PASS,
)

```
result = ReleaseGateEngine().evaluate(gate_input)

assert result.application == "SecureCommerce"
assert result.version == "1.0.0"
assert result.commit_sha == "abc123def456"
```

def test_release_decision_record_contains_timestamp() -> None:
"""Verify the final decision is timestamped."""
gate_input = build_input()

```
result = ReleaseGateEngine().evaluate(gate_input)

assert result.evaluated_at is not None
```

def test_clean_release_has_explanatory_reason() -> None:
"""Verify a clean release still produces an audit explanation."""
gate_input = build_input(
policy_decision=PolicyDecision.PASS,
)

```
result = ReleaseGateEngine().evaluate(gate_input)

assert result.decision == ReleaseDecision.PASS
assert result.reasons
assert any(
    "No configured release-blocking" in reason
    for reason in result.reasons
)
```

def test_review_is_not_reported_as_passed() -> None:
"""Verify review decisions are distinct from successful releases."""
gate_input = build_input(
policy_decision=PolicyDecision.REVIEW,
)

```
result = ReleaseGateEngine().evaluate(gate_input)

assert result.decision == ReleaseDecision.REVIEW
assert result.passed is False
assert result.requires_review is True
```

def test_block_is_not_reported_as_passed() -> None:
"""Verify blocked releases are distinct from successful releases."""
gate_input = build_input(
policy_decision=PolicyDecision.BLOCK,
blocking_findings=["SF-0001"],
)

```
result = ReleaseGateEngine().evaluate(gate_input)

assert result.decision == ReleaseDecision.BLOCK
assert result.passed is False
assert result.is_blocked is True
```
