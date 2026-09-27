"""Tests for regression-gate release integration."""

from secureforge.core.release_gate.regression import (
RegressionGateResult,
build_regression_gate_result,
)
from secureforge.regression import (
RegressionGateDecision,
)

def test_build_regression_gate_result_from_passed_decision() -> None:
"""Convert an allowed regression decision."""
decision = RegressionGateDecision(
allowed=True,
status="passed",
reason=(
"All executed security regression tests passed."
),
failed_tests=(),
errored_tests=(),
skipped_tests=(),
)

```
result = build_regression_gate_result(
    decision
)

assert isinstance(
    result,
    RegressionGateResult,
)
assert result.allowed is True
assert result.blocked is False
assert result.status == "passed"
assert result.reason == (
    "All executed security regression tests passed."
)
assert result.failures == ()
assert result.skipped_tests == ()
assert result.has_failures is False
```

def test_build_regression_gate_result_from_failed_decision() -> None:
"""Convert a blocked regression decision."""
decision = RegressionGateDecision(
allowed=False,
status="failed",
reason=(
"One or more security regression tests failed."
),
failed_tests=(
"BOLA-001",
"SQLI-001",
),
errored_tests=(
"AUTHZ-001",
),
skipped_tests=(
"OPTIONAL-001",
),
)

```
result = build_regression_gate_result(
    decision
)

assert result.allowed is False
assert result.blocked is True
assert result.status == "failed"
assert result.failures == (
    "BOLA-001",
    "SQLI-001",
    "AUTHZ-001",
)
assert result.skipped_tests == (
    "OPTIONAL-001",
)
assert result.has_failures is True
```

def test_regression_gate_result_to_dict() -> None:
"""Serialize the release-gate regression result."""
decision = RegressionGateDecision(
allowed=False,
status="error",
reason=(
"One or more security regression tests "
"could not be executed."
),
failed_tests=(),
errored_tests=(
"BOLA-001",
),
skipped_tests=(),
)

```
result = build_regression_gate_result(
    decision
)

assert result.to_dict() == {
    "allowed": False,
    "blocked": True,
    "status": "error",
    "reason": (
        "One or more security regression tests "
        "could not be executed."
    ),
    "failures": [
        "BOLA-001"
    ],
    "skipped_tests": [],
}
```
