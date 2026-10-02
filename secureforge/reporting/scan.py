"""Build complete reports from scan results."""

from __future__ import annotations

from secureforge.core.scan.models import SecurityScanResult
from .builder import SecurityReportBuilder


def build_scan_report(
    result: SecurityScanResult,
    *,
    release=None,
    scan=None,
):
    """Convert a scan result into the complete reporting model."""
    pipeline = result.pipeline
    return SecurityReportBuilder().build(
        release=release,
        scan=scan,
        findings=list(result.findings),
        risk=pipeline.risk,
        policy=pipeline.policy,
        decision=pipeline.release_gate,
        regression=getattr(pipeline, "regression", None),
        regression_gate=getattr(pipeline, "regression_gate", None),
        validation=getattr(pipeline, "validation", None),
        validation_results=getattr(pipeline, "validation_results", None),
        validation_gate=getattr(pipeline, "validation_gate", None),
    )


__all__ = ["build_scan_report"]
