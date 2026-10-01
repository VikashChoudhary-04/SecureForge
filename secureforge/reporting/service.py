"""Reporting service for SecureForge."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from secureforge.core.scan.models import SecurityScanResult

from .builder import SecurityReportBuilder
from .html import HTMLReportRenderer
from .loader import SecurityReportLoader
from .models import ReleaseMetadata, ScanMetadata, SecurityReport


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
        self.builder = builder or SecurityReportBuilder()
        self.renderer = renderer or HTMLReportRenderer()
        self.loader = loader or SecurityReportLoader()

    def build_report(
        self,
        *,
        release: ReleaseMetadata,
        scan: ScanMetadata,
        findings,
        risk,
        policy,
        decision,
        remediation=None,
        regression=None,
        regression_gate=None,
    ) -> SecurityReport:
        return self.builder.build(
            release=release,
            scan=scan,
            findings=list(findings),
            risk=risk,
            policy=policy,
            decision=decision,
            remediation=remediation,
            regression=regression,
            regression_gate=regression_gate,
        )

    def generate_from_results(
        self,
        *,
        release: ReleaseMetadata,
        scan: ScanMetadata,
        findings,
        risk,
        policy,
        decision,
        paths: ReportPaths,
        remediation=None,
        regression=None,
        regression_gate=None,
    ) -> ReportPaths:
        report = self.build_report(
            release=release,
            scan=scan,
            findings=findings,
            risk=risk,
            policy=policy,
            decision=decision,
            remediation=remediation,
            regression=regression,
            regression_gate=regression_gate,
        )
        self.write_json(report, paths.json_path)
        self.write_html(report, paths.html_path)
        return paths

    def build_from_scan_result(
        self,
        *,
        result: SecurityScanResult,
        release: ReleaseMetadata,
        scan: ScanMetadata,
    ) -> SecurityReport:
        pipeline = result.pipeline
        return self.builder.build(
            release=release,
            scan=scan,
            findings=list(result.findings),
            risk=pipeline.risk,
            policy=pipeline.policy,
            decision=pipeline.release_gate,
            remediation=getattr(pipeline, "remediation", None),
            regression=getattr(pipeline, "regression", None),
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
        report = self.build_from_scan_result(
            result=result,
            release=release,
            scan=scan,
        )
        self.write_json(report, paths.json_path)
        self.write_html(report, paths.html_path)
        return paths

    def generate(
        self,
        report_or_result,
        output_directory: Path | None = None,
        *,
        json_path: Path | None = None,
        html_path: Path | None = None,
    ):
        """Generate reports using either legacy or modern calling style."""
        if isinstance(report_or_result, SecurityReport):
            report = report_or_result
        else:
            if output_directory is None:
                raise ReportingError(
                    "output_directory is required for scan-result generation."
                )
            report = self.build(report_or_result)

        if json_path is None or html_path is None:
            if output_directory is None:
                raise ReportingError(
                    "Both json_path and html_path are required."
                )
            json_path = output_directory / "security-report.json"
            html_path = output_directory / "security-report.html"

        self.write_json(report, json_path)
        self.write_html(report, html_path)
        return ReportPaths(
            json_path=json_path,
            html_path=html_path,
        )

    def build(self, result: SecurityScanResult) -> SecurityReport:
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
            application=execution.application,
            version=execution.version,
            target=getattr(execution, "target", ""),
            started_at=execution.started_at,
            completed_at=execution.completed_at,
        )
        return self.build_from_scan_result(
            result=result,
            release=release,
            scan=scan,
        )

    def write_json(self, report: SecurityReport, output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
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

    def write_html(self, report: SecurityReport, output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            output_path.write_text(
                self.renderer.render(report),
                encoding="utf-8",
            )
        except OSError as exc:
            raise ReportingError(
                f"Unable to write HTML report: {exc}"
            ) from exc
        return output_path

    def load(self, input_path: Path) -> SecurityReport:
        return self.loader.load(input_path)


class ReportingService(SecurityReportService):
    """Backward-compatible reporting service."""

    def generate(
        self,
        result: SecurityScanResult,
        output_directory: Path,
    ) -> SecurityReport:
        output_directory.mkdir(parents=True, exist_ok=True)
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
