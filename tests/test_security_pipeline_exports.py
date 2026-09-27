```python id="r8k4wm"
"""Tests for SecureForge security-pipeline exports."""

from secureforge.core.scan import (
    SecurityPipeline,
    SecurityPipelineResult,
)


def test_security_pipeline_exports() -> None:
    """Verify the public security-pipeline API."""
    assert SecurityPipeline is not None
    assert SecurityPipelineResult is not None

    assert hasattr(
        SecurityPipeline,
        "evaluate",
    )

    assert hasattr(
        SecurityPipeline,
        "summarize",
    )
```
