"""Tests for regression integration in the SecureForge security pipeline."""

from secureforge.core.scan.security_pipeline import (
SecurityPipeline,
)
from secureforge.regression import (
RegressionResult,
RegressionStatus,
RegressionSuiteResult,
)

def build_regression_result(
*,
test_id: str,
status: RegressionStatus,
) -> RegressionResult:
"""Build a regression result for pipeline tests."""
return RegressionResult(
test_id=test_id,
security_requirement="SF-AUTHZ-001",
status=status,
expected="Access must be denied.",
actual=(
"Access was denied."
if status == RegressionStatus.PASSED
else "Unauthorized access was observed."
),
message=(
"Regression test passed."
if status == RegressionStatus.PASSED
else "Regression test failed."
),
evidence={},
started_at="2026-09-27T10:00:00+00:00",
completed_at="2026-09-27T10:00:01+00:00",
duration_seconds=1.0,
metadata={},
)

def build_regression_suite(
*,
status: RegressionStatus,
result_status: RegressionStatus,
) -> RegressionSuiteResult:
"""Build a regression suite result for pipeline tests."""
result = build_regression_result(
test_id="BOLA-001",
status=result_status,
)

```
return RegressionSuiteResult(
    suite_id="securecommerce-regression",
    name="SecureCommerce Regression",
    status=status,
    results=[result],
    started_at="2026-09-27T10:00:00+00:00",
    completed_at="2026-09-27T10:00:01+00:00",
    duration_seconds=1.0,
)
```

def test_pipeline_blocks_when_regression_fails(
sample_findings,
) -> None:
"""Block the release when a regression test fails."""
regression = build_regression_suite(
status=RegressionStatus.FAILED,
result_status=RegressionStatus.FAILED,
)

```
pipeline = SecurityPipeline()

result = pipeline.evaluate(
    sample_findings,
    regression=regression,
)

assert result.regression is regression
assert result.regression_gate is not None
assert result.regression_gate.allowed is False
assert result.regression_gate.blocked is True
assert result.regression_gate.failed_tests == (
    "BOLA-001",
)
assert result.release_allowed is False
assert result.release_blocked is True
```

def test_pipeline_allows_release_when_regression_passes(
sample_findings,
) -> None:
"""Allow the release when all regression tests pass."""
regression = build_regression_suite(
status=RegressionStatus.PASSED,
result_status=RegressionStatus.PASSED,
)

```
pipeline = SecurityPipeline()

result = pipeline.evaluate(
    sample_findings,
    regression=regression,
)

assert result.regression is regression
assert result.regression_gate is not None
assert result.regression_gate.allowed is True
assert result.regression_gate.blocked is False
assert result.release_allowed is True
```

def test_pipeline_can_accept_explicit_regression_gate(
sample_findings,
) -> None:
"""Use an explicitly supplied regression-gate decision."""
regression = build_regression_suite(
status=RegressionStatus.PASSED,
result_status=RegressionStatus.PASSED,
)

```
explicit_gate = pipeline_gate = (
    __import__(
        "secureforge.regression",
        fromlist=[
            "RegressionGateDecision"
        ],
    ).RegressionGateDecision(
        allowed=False,
        status="failed",
        reason="Explicit regression gate failure.",
        failed_tests=("MANUAL-001",),
        errored_tests=(),
        skipped_tests=(),
    )
)

pipeline = SecurityPipeline()

result = pipeline.evaluate(
    sample_findings,
    regression=regression,
    regression_gate=explicit_gate,
)

assert result.regression_gate is pipeline_gate
assert result.regression_gate.allowed is False
assert result.regression_gate.failed_tests == (
    "MANUAL-001",
)
assert result.release_allowed is False
```

def test_pipeline_summary_contains_regression_information(
sample_findings,
) -> None:
"""Include regression data in the pipeline summary."""
regression = build_regression_suite(
status=RegressionStatus.FAILED,
result_status=RegressionStatus.FAILED,
)

```
pipeline = SecurityPipeline()

result = pipeline.evaluate(
    sample_findings,
    regression=regression,
)

summary = pipeline.summarize(
    result
)

assert "regression" in summary
assert summary["regression"]["suite_id"] == (
    "securecommerce-regression"
)
assert summary["regression"]["failed"] == 1

assert "regression_gate" in summary
assert (
    summary["regression_gate"]["allowed"]
    is False
)
assert summary["regression_gate"]["blocked"] is True
assert summary["regression_gate"]["failures"] == [
    "BOLA-001"
]
```
