```python id="j2m8q4"
"""Tests for regression integration in the security pipeline."""

from secureforge.core.scan.security_pipeline import (
    SecurityPipeline,
)
from secureforge.regression import (
    RegressionGateDecision,
    RegressionResult,
    RegressionStatus,
    RegressionSuiteResult,
)


def test_pipeline_includes_regression_result(
    sample_findings,
) -> None:
    """Include regression-suite results in the pipeline result."""
    pipeline = SecurityPipeline()

    regression = RegressionSuiteResult(
        suite_id="securecommerce-regression",
        status=RegressionStatus.PASSED,
        total=2,
        passed=2,
        failed=0,
        errors=0,
        skipped=0,
        results=[
            RegressionResult(
                test_id="BOLA-001",
                status=RegressionStatus.PASSED,
                message="BOLA protection verified.",
            ),
            RegressionResult(
                test_id="SQLI-001",
                status=RegressionStatus.PASSED,
                message="SQL injection protection verified.",
            ),
        ],
    )

    result = pipeline.evaluate(
        sample_findings,
        regression=regression,
    )

    assert result.regression == regression
    assert result.regression_gate is not None
    assert result.regression_gate.allowed is True
    assert result.regression_gate.blocked is False


def test_pipeline_blocks_on_failed_regression(
    sample_findings,
) -> None:
    """A failed regression must block the release."""
    pipeline = SecurityPipeline()

    regression = RegressionSuiteResult(
        suite_id="securecommerce-regression",
        status=RegressionStatus.FAILED,
        total=1,
        passed=0,
        failed=1,
        errors=0,
        skipped=0,
        results=[
            RegressionResult(
                test_id="BOLA-001",
                status=RegressionStatus.FAILED,
                message="BOLA protection failed.",
            )
        ],
    )

    result = pipeline.evaluate(
        sample_findings,
        regression=regression,
    )

    assert result.regression == regression
    assert result.regression_gate is not None
    assert result.regression_gate.allowed is False
    assert result.regression_gate.blocked is True
    assert "BOLA-001" in (
        result.regression_gate.failures
    )

    assert result.release_blocked is True
    assert result.release_allowed is False


def test_pipeline_blocks_on_regression_error(
    sample_findings,
) -> None:
    """A regression execution error must block the release."""
    pipeline = SecurityPipeline()

    regression = RegressionSuiteResult(
        suite_id="securecommerce-regression",
        status=RegressionStatus.ERROR,
        total=1,
        passed=0,
        failed=0,
        errors=1,
        skipped=0,
        results=[
            RegressionResult(
                test_id="AUTHZ-001",
                status=RegressionStatus.ERROR,
                message="Regression test could not execute.",
            )
        ],
    )

    result = pipeline.evaluate(
        sample_findings,
        regression=regression,
    )

    assert result.regression_gate is not None
    assert result.regression_gate.allowed is False
    assert result.regression_gate.blocked is True
    assert "AUTHZ-001" in (
        result.regression_gate.failures
    )

    assert result.release_allowed is False
    assert result.release_blocked is True


def test_pipeline_accepts_explicit_regression_gate(
    sample_findings,
) -> None:
    """Use an explicitly supplied regression-gate decision."""
    pipeline = SecurityPipeline()

    regression = RegressionSuiteResult(
        suite_id="securecommerce-regression",
        status=RegressionStatus.PASSED,
        total=1,
        passed=1,
        failed=0,
        errors=0,
        skipped=0,
        results=[
            RegressionResult(
                test_id="BOLA-001",
                status=RegressionStatus.PASSED,
                message="BOLA protection verified.",
            )
        ],
    )

    gate = RegressionGateDecision(
        allowed=False,
        status="failed",
        reason="Regression gate intentionally blocks release.",
        failed_tests=("BOLA-001",),
        errored_tests=(),
        skipped_tests=(),
    )

    result = pipeline.evaluate(
        sample_findings,
        regression=regression,
        regression_gate=gate,
    )

    assert result.regression == regression
    assert result.regression_gate == gate

    assert result.release_allowed is False
    assert result.release_blocked is True


def test_pipeline_serializes_regression_sections(
    sample_findings,
) -> None:
    """Serialize regression results and gate decisions."""
    pipeline = SecurityPipeline()

    regression = RegressionSuiteResult(
        suite_id="securecommerce-regression",
        status=RegressionStatus.FAILED,
        total=1,
        passed=0,
        failed=1,
        errors=0,
        skipped=0,
        results=[
            RegressionResult(
                test_id="BOLA-001",
                status=RegressionStatus.FAILED,
                message="BOLA protection failed.",
            )
        ],
    )

    result = pipeline.evaluate(
        sample_findings,
        regression=regression,
    )

    payload = result.to_dict()

    assert "regression" in payload
    assert "regression_gate" in payload

    assert (
        payload["regression"]["suite_id"]
        == "securecommerce-regression"
    )

    assert (
        payload["regression_gate"]["allowed"]
        is False
    )

    assert (
        "BOLA-001"
        in payload["regression_gate"]["failures"]
    )
```
