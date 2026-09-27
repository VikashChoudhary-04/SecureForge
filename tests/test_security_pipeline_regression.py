```python id="q7m3vx"
"""Tests for SecureForge security-pipeline regression integration."""

from secureforge.core.scan.security_pipeline import (
    SecurityPipeline,
)
from secureforge.regression import (
    RegressionGateDecision,
    RegressionResult,
    RegressionStatus,
    RegressionSuiteResult,
)


def _build_regression_suite_result(
    *,
    failed: int = 0,
    errors: int = 0,
    skipped: int = 0,
) -> RegressionSuiteResult:
    """Build a minimal regression-suite result."""
    results: list[RegressionResult] = []

    if failed:
        results.append(
            RegressionResult(
                test_id="BOLA-001",
                status=RegressionStatus.FAILED,
                message="Regression failed.",
            )
        )

    if errors:
        results.append(
            RegressionResult(
                test_id="SQLI-001",
                status=RegressionStatus.ERROR,
                message="Regression execution errored.",
            )
        )

    if skipped:
        results.append(
            RegressionResult(
                test_id="XSS-001",
                status=RegressionStatus.SKIPPED,
                message="Regression skipped.",
            )
        )

    return RegressionSuiteResult(
        suite_id="securecommerce-regression",
        status=(
            RegressionStatus.FAILED
            if failed
            else RegressionStatus.ERROR
            if errors
            else RegressionStatus.SKIPPED
            if skipped
            else RegressionStatus.PASSED
        ),
        results=results,
    )


def test_pipeline_derives_regression_gate_from_suite_result(
    sample_finding,
) -> None:
    """Derive a regression gate when only suite results are supplied."""
    pipeline = SecurityPipeline()

    regression = _build_regression_suite_result()

    result = pipeline.evaluate(
        [sample_finding],
        regression=regression,
    )

    assert result.regression is regression
    assert result.regression_gate is not None
    assert result.regression_gate.allowed is True
    assert (
        result.regression_gate.status
        == RegressionStatus.PASSED.value
    )


def test_pipeline_blocks_on_failed_regression(
    sample_finding,
) -> None:
    """A failed regression test must block the release."""
    pipeline = SecurityPipeline()

    regression = _build_regression_suite_result(
        failed=1
    )

    result = pipeline.evaluate(
        [sample_finding],
        regression=regression,
    )

    assert result.regression_gate is not None
    assert result.regression_gate.allowed is False
    assert result.regression_gate.blocked is True
    assert (
        result.regression_gate.status
        == RegressionStatus.FAILED.value
    )
    assert (
        "BOLA-001"
        in result.regression_gate.failed_tests
    )

    assert result.release_blocked is True


def test_pipeline_blocks_on_regression_error(
    sample_finding,
) -> None:
    """A regression execution error must block the release."""
    pipeline = SecurityPipeline()

    regression = _build_regression_suite_result(
        errors=1
    )

    result = pipeline.evaluate(
        [sample_finding],
        regression=regression,
    )

    assert result.regression_gate is not None
    assert result.regression_gate.allowed is False
    assert (
        result.regression_gate.status
        == RegressionStatus.ERROR.value
    )
    assert (
        "SQLI-001"
        in result.regression_gate.errored_tests
    )

    assert result.release_blocked is True


def test_pipeline_preserves_explicit_regression_gate(
    sample_finding,
) -> None:
    """Use an explicitly supplied regression gate decision."""
    pipeline = SecurityPipeline()

    regression = _build_regression_suite_result()

    explicit_gate = RegressionGateDecision(
        allowed=False,
        status=RegressionStatus.FAILED.value,
        reason="Explicit regression gate failure.",
        failed_tests=("AUTHZ-001",),
        errored_tests=(),
        skipped_tests=(),
    )

    result = pipeline.evaluate(
        [sample_finding],
        regression=regression,
        regression_gate=explicit_gate,
    )

    assert (
        result.regression_gate
        is explicit_gate
    )

    assert result.release_blocked is True


def test_pipeline_accepts_skipped_regression_suite(
    sample_finding,
) -> None:
    """A skipped suite produces an explicit skipped gate state."""
    pipeline = SecurityPipeline()

    regression = _build_regression_suite_result(
        skipped=1
    )

    result = pipeline.evaluate(
        [sample_finding],
        regression=regression,
    )

    assert result.regression_gate is not None
    assert (
        result.regression_gate.status
        == RegressionStatus.SKIPPED.value
    )
    assert result.regression_gate.allowed is True


def test_pipeline_without_regression_has_no_regression_gate(
    sample_finding,
) -> None:
    """No regression input should leave the regression gate unset."""
    pipeline = SecurityPipeline()

    result = pipeline.evaluate(
        [sample_finding]
    )

    assert result.regression is None
    assert result.regression_gate is None


def test_pipeline_summary_includes_regression_data(
    sample_finding,
) -> None:
    """Include regression information in the pipeline summary."""
    pipeline = SecurityPipeline()

    regression = _build_regression_suite_result(
        failed=1
    )

    result = pipeline.evaluate(
        [sample_finding],
        regression=regression,
    )

    summary = pipeline.summarize(
        result
    )

    assert "regression" in summary
    assert (
        summary["regression"]["suite_id"]
        == "securecommerce-regression"
    )

    assert (
        summary["regression_gate"]["blocked"]
        is True
    )
```
