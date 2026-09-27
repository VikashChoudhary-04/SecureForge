```python id="c7m2v9"
"""Tests for SecureForge security-pipeline exports."""

from secureforge.core.scan.security_pipeline import (
    SecurityPipeline,
    SecurityPipelineResult,
)


def test_security_pipeline_exports() -> None:
    """Expose the security-pipeline public classes."""
    assert SecurityPipeline.__name__ == (
        "SecurityPipeline"
    )

    assert SecurityPipelineResult.__name__ == (
        "SecurityPipelineResult"
    )


def test_security_pipeline_module_exports() -> None:
    """Keep the intended security-pipeline API stable."""
    import secureforge.core.scan.security_pipeline as module

    assert hasattr(
        module,
        "SecurityPipeline",
    )

    assert hasattr(
        module,
        "SecurityPipelineResult",
    )


def test_security_pipeline_result_public_properties(
    sample_findings,
) -> None:
    """Expose release-state properties on pipeline results."""
    pipeline = SecurityPipeline()

    result = pipeline.evaluate(
        sample_findings
    )

    assert isinstance(
        result,
        SecurityPipelineResult,
    )

    assert isinstance(
        result.release_allowed,
        bool,
    )

    assert isinstance(
        result.release_blocked,
        bool,
    )

    assert (
        result.release_allowed
        == result.release_gate.release_allowed
    )

    assert (
        result.release_blocked
        == (
            not result.release_allowed
        )
    )


def test_security_pipeline_result_to_dict(
    sample_findings,
) -> None:
    """Expose a complete dictionary representation."""
    pipeline = SecurityPipeline()

    result = pipeline.evaluate(
        sample_findings
    )

    payload = result.to_dict()

    assert isinstance(
        payload,
        dict,
    )

    assert set(
        (
            "findings",
            "risk",
            "policy",
            "release_gate",
        )
    ).issubset(
        payload.keys()
    )
```
