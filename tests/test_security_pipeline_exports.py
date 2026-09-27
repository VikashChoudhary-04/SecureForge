"""Tests for SecureForge security-pipeline exports."""

from secureforge.core.scan import (
SecurityPipeline,
SecurityPipelineResult,
)

def test_security_pipeline_exports() -> None:
"""Verify the public security-pipeline API exports."""
assert SecurityPipeline is not None
assert SecurityPipelineResult is not None
