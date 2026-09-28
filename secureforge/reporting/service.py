"""Reporting service for SecureForge."""

from __future__ import annotations

import json
from pathlib import Path

from secureforge.core.scan.models import SecurityScanResult

from .html import HTMLReportRenderer
from .loader import SecurityReportLoader
from .models import SecurityReport
from .scan import build_scan_report


class ReportingError(Exception):
    """Raised when report generation fails."""


class ReportingService:
    """Generate and persist SecureForge security reports."""

    def __init__(
        self,
        *,
        renderer: HTMLReportRenderer | None = None,
        loader: SecurityReportLoader | None = None,
    ) -> None:
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

    def build(
        self,
        result: SecurityScanResult,
    ) -> SecurityReport:
        """Build a validated security report."""
        return build_scan_report(result)

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

    def load(
        self,
        input_path: Path,
    ) -> SecurityReport:
        """Load and validate an existing security report."""
        return self.loader.load(input_path)


__all__ = [
    "ReportingError",
    "ReportingService",
]
