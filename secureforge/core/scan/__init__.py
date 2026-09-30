"""Scan models and orchestration components for SecureForge."""

from .executor import (
    ScanExecutionError,
    ScanExecutor,
    ToolExecutor,
    build_scan_executor,
)
from .factory import ScanRunFactory
from .models import (
    ScanConfiguration,
    ScanExecution,
    ScanProfile,
    ScanRun,
    ScanStatus,
    ScanSummary,
    SecurityScanResult,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from .normalizer import ScanResultNormalizer

# Backward-compatible public name used by the scan package API.
ScanEvidenceNormalizer = ScanResultNormalizer

from .orchestrator import ScanOrchestrator
from .planner import (
    ScanPlan,
    ScanPlanner,
)
from .runner import ScanRunner
from .security_pipeline import (
    SecurityPipeline,
    SecurityPipelineResult,
)
from .store import (
    ScanResultStore,
    ScanResultStoreError,
)


__all__ = [
    "ScanConfiguration",
    "ScanEvidenceNormalizer",
    "ScanExecution",
    "ScanExecutionError",
    "ScanExecutor",
    "ScanOrchestrator",
    "ScanPlan",
    "ScanPlanner",
    "ScanProfile",
    "ScanResultNormalizer",
    "ScanResultStore",
    "ScanResultStoreError",
    "ScanRun",
    "ScanRunFactory",
    "ScanRunner",
    "ScanStatus",
    "ScanSummary",
    "SecurityPipeline",
    "SecurityPipelineResult",
    "SecurityScanResult",
    "ToolExecutionResult",
    "ToolExecutionStatus",
    "ToolExecutor",
    "build_scan_executor",
]
