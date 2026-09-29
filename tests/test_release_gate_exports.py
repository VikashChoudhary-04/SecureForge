"""Tests for SecureForge release-gate package exports."""

from secureforge.core.release_gate import (
    RegressionGateResult,
    ReleaseGateAction,
    ReleaseGateDecision,
    ReleaseGateEngine,
    ReleaseGateEvaluator,
    ReleaseGateStatus,
    build_regression_gate_result,
)


def test_release_gate_exports_are_available() -> None:
    """Expose all intended release-gate components."""
    exported = [
        ReleaseGateAction,
        ReleaseGateDecision,
        ReleaseGateEngine,
        ReleaseGateEvaluator,
        ReleaseGateStatus,
        RegressionGateResult,
        build_regression_gate_result,
    ]

    assert all(
        item is not None
        for item in exported
    )


def test_release_gate_public_api_is_stable() -> None:
    """Keep the intended release-gate API names available."""
    import secureforge.core.release_gate as release_gate

    expected = {
        "ReleaseGateAction",
        "ReleaseGateDecision",
        "ReleaseGateEngine",
        "ReleaseGateEvaluator",
        "ReleaseGateStatus",
        "RegressionGateResult",
        "build_regression_gate_result",
    }

    assert expected.issubset(
        set(release_gate.__all__)
    )


def test_release_gate_exports_reference_expected_objects() -> None:
    """Verify exported names reference the expected implementations."""
    import secureforge.core.release_gate as release_gate

    assert release_gate.ReleaseGateEngine.__name__ == (
        "ReleaseGateEngine"
    )

    assert release_gate.ReleaseGateEvaluator.__name__ == (
        "ReleaseGateEvaluator"
    )

    assert release_gate.RegressionGateResult.__name__ == (
        "RegressionGateResult"
    )

    assert (
        release_gate.build_regression_gate_result.__name__
        == "build_regression_gate_result"
    )
