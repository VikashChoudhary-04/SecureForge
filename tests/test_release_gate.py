"""Tests for the SecureForge release-gate engine."""

from secureforge.core.policy import PolicyDecision
from secureforge.core.release_gate import (
ReleaseDecision,
ReleaseDecisionEvaluator,
ReleaseGateEngine,
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

def test_clean_release_passes() -> None:
"""Verify a clean release receives PASS."""
engine = ReleaseGateEngine()

```
result = engine.evaluate(
    build_input()
)

assert result.decision == ReleaseDecision.PASS
assert result.passed is True
assert result.requires_review is False
assert result.is_blocked is False
```

def test_policy_block_produces_block() -> None:
"""Verify a BLOCK policy decision reaches the release record."""
engine = ReleaseGateEngine()

```
result = engine.evaluate(
    build_input(
        policy_decision=ReleaseDecision.BLOCK
    )
)

assert result.decision == ReleaseDecision.BLOCK
assert result.is_blocked is True
```

def test_policy_review_produces_review() -> None:
"""Verify a REVIEW policy decision reaches the release record."""
engine = ReleaseGateEngine()

```
result = engine.evaluate(
    build_input(
        policy_decision=ReleaseDecision.REVIEW
    )
)

assert result.decision == ReleaseDecision.REVIEW
assert result.requires_review is True
```

def test_blocking_findings_block_release() -> None:
"""Verify blocking findings prevent release."""
engine = ReleaseGateEngine()

```
result = engine.evaluate(
    build_input(
        blocking_findings=[
            "SF-001"
        ]
    )
)

assert result.decision == ReleaseDecision.BLOCK
assert result.blocking_findings == [
    "SF-001"
]
assert result.is_blocked is True
```

def test_failed_regression_blocks_release() -> None:
"""Verify failed security regression tests block release."""
engine = ReleaseGateEngine()

```
result = engine.evaluate(
    build_input(
        failed_regressions=[
            "BOLA-001"
        ]
    )
)

assert result.decision == ReleaseDecision.BLOCK
assert result.failed_regressions == [
    "BOLA-001"
]
```

def test_review_findings_require_review() -> None:
"""Verify review findings require security review."""
engine = ReleaseGateEngine()

```
result = engine.evaluate(
    build_input(
        review_findings=[
            "SF-002"
        ]
    )
)

assert result.decision == ReleaseDecision.REVIEW
assert result.review_findings == [
    "SF-002"
]
```

def test_tool_errors_require_review() -> None:
"""Verify integration errors raise a clean release to REVIEW."""
engine = ReleaseGateEngine()

```
result = engine.evaluate(
    build_input(
        tool_errors=[
            "DAST execution failed."
        ]
    )
)

assert result.decision == ReleaseDecision.REVIEW
assert result.tool_errors == [
    "DAST execution failed."
]
```

def test_block_takes_precedence_over_review() -> None:
"""Verify BLOCK has higher precedence than REVIEW."""
engine = ReleaseGateEngine()

```
result = engine.evaluate(
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

assert result.decision == ReleaseDecision.BLOCK
```

def test_regression_failure_takes_precedence_over_review() -> None:
"""Verify a regression failure upgrades REVIEW to BLOCK."""
engine = ReleaseGateEngine()

```
result = engine.evaluate(
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

assert result.decision == ReleaseDecision.BLOCK
```

def test_exception_is_preserved_in_release_record() -> None:
"""Verify applied policy exceptions are preserved."""
engine = ReleaseGateEngine()

```
result = engine.evaluate(
    build_input(
        exceptions_applied=[
            "EXC-001"
        ]
    )
)

assert result.decision == ReleaseDecision.PASS
assert result.exceptions_applied == [
    "EXC-001"
]
assert (
    "One or more configured policy exceptions "
    "were applied."
    in result.reasons
)
```

def test_release_metadata_is_preserved() -> None:
"""Verify release metadata survives gate evaluation."""
gate_input = build_input()
gate_input.metadata = {
"profile": "standard",
"environment": "lab",
}

```
engine = ReleaseGateEngine()

result = engine.evaluate(
    gate_input
)

assert result.metadata == {
    "profile": "standard",
    "environment": "lab",
}
```

def test_application_version_and_commit_are_preserved() -> None:
"""Verify release identity fields are preserved."""
engine = ReleaseGateEngine()

```
result = engine.evaluate(
    build_input()
)

assert result.application == "SecureCommerce"
assert result.version == "1.0.0"
assert result.commit_sha == "abc123"
```

def test_custom_evaluator_can_be_injected() -> None:
"""Verify the release engine supports evaluator injection."""
class StubEvaluator:
def evaluate(
self,
gate_input: ReleaseGateInput,
) -> tuple[ReleaseDecision, list[str]]:
return (
ReleaseDecision.BLOCK,
["Stub evaluator decision."],
)

```
engine = ReleaseGateEngine(
    evaluator=StubEvaluator()
)

result = engine.evaluate(
    build_input()
)

assert result.decision == ReleaseDecision.BLOCK
assert result.reasons == [
    "Stub evaluator decision."
]
```

def test_default_engine_uses_release_decision_evaluator() -> None:
"""Verify the default engine uses the production evaluator."""
engine = ReleaseGateEngine()

```
assert isinstance(
    engine.evaluator,
    ReleaseDecisionEvaluator,
)
```

def test_multiple_conditions_are_preserved() -> None:
"""Verify all release-gate inputs remain visible in the record."""
engine = ReleaseGateEngine()

```
result = engine.evaluate(
    build_input(
        review_findings=[
            "SF-002"
        ],
        blocking_findings=[
            "SF-001"
        ],
        failed_regressions=[
            "BOLA-001"
        ],
        tool_errors=[
            "Nmap failed."
        ],
        exceptions_applied=[
            "EXC-001"
        ],
    )
)

assert result.decision == ReleaseDecision.BLOCK
assert result.blocking_findings == ["SF-001"]
assert result.review_findings == ["SF-002"]
assert result.failed_regressions == ["BOLA-001"]
assert result.tool_errors == ["Nmap failed."]
assert result.exceptions_applied == ["EXC-001"]
```

def test_release_record_properties_match_decision() -> None:
"""Verify convenience properties reflect the final decision."""
engine = ReleaseGateEngine()

```
pass_result = engine.evaluate(
    build_input(
        policy_decision=ReleaseDecision.PASS
    )
)

review_result = engine.evaluate(
    build_input(
        policy_decision=ReleaseDecision.REVIEW
    )
)

block_result = engine.evaluate(
    build_input(
        policy_decision=ReleaseDecision.BLOCK
    )
)

assert pass_result.passed is True
assert pass_result.requires_review is False
assert pass_result.is_blocked is False

assert review_result.passed is False
assert review_result.requires_review is True
assert review_result.is_blocked is False

assert block_result.passed is False
assert block_result.requires_review is False
assert block_result.is_blocked is True
```

def test_policy_decision_enum_is_compatible_with_release_input() -> None:
"""Verify release input accepts the policy decision values."""
gate_input = ReleaseGateInput(
application="SecureCommerce",
version="1.0.0",
policy_decision=PolicyDecision.BLOCK,
)

```
assert gate_input.policy_decision == ReleaseDecision.BLOCK
```
