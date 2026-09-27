"""Tests for SecureForge scan package exports."""

from secureforge.core.scan import (
ScanEvidenceNormalizer,
ScanExecution,
ScanExecutionError,
ScanExecutor,
ScanOrchestrator,
ScanPlan,
ScanPlanner,
ScanRunner,
ScanStatus,
SecurityPipeline,
SecurityPipelineResult,
SecurityScanResult,
ToolExecutionResult,
build_scan_executor,
)

def test_scan_exports() -> None:
"""Verify the public scan API exports."""
assert ScanEvidenceNormalizer is not None
assert ScanExecution is not None
assert ScanExecutionError is not None
assert ScanExecutor is not None
assert ScanOrchestrator is not None
assert ScanPlan is not None
assert ScanPlanner is not None
assert ScanRunner is not None
assert ScanStatus is not None
assert SecurityPipeline is not None
assert SecurityPipelineResult is not None
assert SecurityScanResult is not None
assert ToolExecutionResult is not None
assert build_scan_executor is not None
