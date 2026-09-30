"""Reporting service for SecureForge."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from secureforge.core.scan.models import SecurityScanResult

from .builder import SecurityReportBuilder
from .html import HTMLReportRenderer
from .loader import SecurityReportLoader
from .models import (
    ReleaseMetadata,
    ScanMetadata,
    SecurityReport,
)


@dataclass(frozen=True)
class ReportPaths:
    """Paths for persisted security report artifacts."""

    json_path: Path
    html_path: Path


class ReportingError(Exception):
    """Raised when report generation fails."""


class SecurityReportService:
    """Build, validate, and persist complete SecureForge security reports."""

    def __init__(
        self,
        *,
        builder: SecurityReportBuilder | None = None,
        renderer: HTMLReportRenderer | None = None,
        loader: SecurityReportLoader | None = None,
    ) -> None:
        self.builder = (
            builder
            if builder is not None
            else SecurityReportBuilder()
        )
        self.renderer = (
            renderer
            if renderer is not None
            else HTMLReportRenderer()
        )
        self.loader = (
            loader
            if loader is not None
            else SecurityReportLoader()
        )

    def build_from_scan_result(
        self,
        *,
        result: SecurityScanResult,
        release: ReleaseMetadata,
        scan: ScanMetadata,
    ) -> SecurityReport:
        """Build a complete security report from a completed scan result."""
        pipeline = result.pipeline

        return self.builder.build(
            release=release,
            scan=scan,
            findings=list(result.findings),
            risk=pipeline.risk,
            policy=pipeline.policy,
            decision=pipeline.release_gate,
            remediation=getattr(
                pipeline,
                "remediation",
                None,
            ),
            regression=getattr(
                pipeline,
                "regression",
                None,
            ),
            regression_gate=getattr(
                pipeline,
                "regression_gate",
                None,
            ),
        )

    def generate_from_scan_result(
        self,
        *,
        result: SecurityScanResult,
        release: ReleaseMetadata,
        scan: ScanMetadata,
        paths: ReportPaths,
    ) -> ReportPaths:
        """Build and persist JSON and HTML reports from a scan result."""
        report = self.build_from_scan_result(
            result=result,
            release=release,
            scan=scan,
        )

        self.write_json(
            report,
            paths.json_path,
        )

        self.write_html(
            report,
            paths.html_path,
        )

        return paths

    def write_json(
        self,
        report: SecurityReport,
        output_path: Path,
    ) -> Path:
        """Write a security report as JSON."""
        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        try:
            output_path.write_text(
                json.dumps(
                    report.model_dump(mode="json"),
                    indent=2,
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
        except OSError as exc:
            raise ReportingError(
                f"Unable to write JSON report: {exc}"
            ) from exc

        return output_path

    def write_html(
        self,
        report: SecurityReport,
        output_path: Path,
    ) -> Path:
        """Render and write a security report as HTML."""
        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        try:
            html = self.renderer.render(report)

            output_path.write_text(
                html,
                encoding="utf-8",
            )
        except OSError as exc:
            raise ReportingError(
                f"Unable to write HTML report: {exc}"
            ) from exc

        return output_path

    def load(
        self,
        input_path: Path,
    ) -> SecurityReport:
        """Load and validate an existing security report."""
        return self.loader.load(input_path)


class ReportingService(SecurityReportService):
    """Backward-compatible reporting service."""

    def build(
        self,
        result: SecurityScanResult,
    ) -> SecurityReport:
        """Build a security report using scan execution metadata."""
        execution = result.execution

        release = ReleaseMetadata(
            application=execution.application,
            version=execution.version,
            commit_sha=execution.commit_sha,
            environment=execution.environment,
        )

        scan = ScanMetadata(
            scan_id=execution.scan_id,
            profile=execution.profile,
            target=execution.target,
            started_at=execution.started_at,
            completed_at=execution.completed_at,
        )

        return self.build_from_scan_result(
            result=result,
            release=release,
            scan=scan,
        )

    def generate(
        self,
        result: SecurityScanResult,
        output_directory: Path,
    ) -> SecurityReport:
        """Build and persist both JSON and HTML reports."""
        output_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        report = self.build(result)

        self.write_json(
            report,
            output_directory / "security-report.json",
        )

        self.write_html(
            report,
            output_directory / "security-report.html",
        )

        return report


__all__ = [
    "ReportPaths",
    "ReportingError",
    "ReportingService",
    "SecurityReportService",
]
