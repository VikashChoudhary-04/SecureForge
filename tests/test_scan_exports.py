```python
"""Tests for SecureForge scan-package exports."""

from secureforge.core.scan import (
    ScanEvidenceNormalizer,
    ScanExecution,
    ScanExecutionError,
    ScanExecutor,
    ScanOrchestrator,
    ScanPlan,
    ScanPlanner,
    ScanResultStore,
    ScanResultStoreError,
    ScanRunner,
    ScanStatus,
    SecurityPipeline,
    SecurityPipelineResult,
    SecurityScanResult,
    ToolExecutionResult,
    build_scan_executor,
)


def test_scan_exports_are_available() -> None:
    """Expose the public scan components from one package."""
    exported = [
        ScanEvidenceNormalizer,
        ScanExecution,
        ScanExecutionError,
        ScanExecutor,
        ScanOrchestrator,
        ScanPlan,
        ScanPlanner,
        ScanResultStore,
        ScanResultStoreError,
        ScanRunner,
        ScanStatus,
        SecurityPipeline,
        SecurityPipelineResult,
        SecurityScanResult,
        ToolExecutionResult,
        build_scan_executor,
    ]

    assert all(
        item is not None
        for item in exported
    )


def test_scan_export_names_are_stable() -> None:
    """Keep the intended public API names available."""
    import secureforge.core.scan as scan

    expected = {
        "ScanEvidenceNormalizer",
        "ScanExecution",
        "ScanExecutionError",
        "ScanExecutor",
        "ScanOrchestrator",
        "ScanPlan",
        "ScanPlanner",
        "ScanResultStore",
        "ScanResultStoreError",
        "ScanRunner",
        "ScanStatus",
        "SecurityPipeline",
        "SecurityPipelineResult",
        "SecurityScanResult",
        "ToolExecutionResult",
        "build_scan_executor",
    }

    assert expected.issubset(
        set(scan.__all__)
    )


def test_scan_exports_reference_expected_objects() -> None:
    """Verify exported names reference the intended implementations."""
    import secureforge.core.scan as scan

    assert scan.ScanExecutor.__name__ == (
        "ScanExecutor"
    )

    assert scan.ScanOrchestrator.__name__ == (
        "ScanOrchestrator"
    )

    assert scan.SecurityPipeline.__name__ == (
        "SecurityPipeline"
    )

    assert scan.ScanResultStore.__name__ == (
        "ScanResultStore"
    )

    assert scan.build_scan_executor.__name__ == (
        "build_scan_executor"
    )
```
