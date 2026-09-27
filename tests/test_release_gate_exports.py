"""Tests for SecureForge release-gate package exports."""

from secureforge.core.release_gate import (
RegressionGateResult,
ReleaseGateDecision,
ReleaseGateEngine,
ReleaseGateEvaluator,
ReleaseGateStatus,
build_regression_gate_result,
)

def test_release_gate_exports() -> None:
"""Verify the public release-gate API exports."""
assert ReleaseGateDecision is not None
assert ReleaseGateEngine is not None
assert ReleaseGateEvaluator is not None
assert ReleaseGateStatus is not None

```
assert RegressionGateResult is not None
assert build_regression_gate_result is not None
```
