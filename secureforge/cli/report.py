"""SecureForge report command service."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from secureforge.core.scan.models import SecurityScanResult
from secureforge.reporting import (
    ReportingService,
    SecurityReport,
)


@dataclass(frozen=True)
class ReportCommandConfiguration:
    """Configuration supplied to the SecureForge report command."""

    release_id: str = "unknown"
    application: str = "unknown"
    version: str = "unknown"
    commit_sha: str = "unknown"
    environment: str = "lab"
    scan_id: str = "unknown"
    profile: str = "standard"
    scan_status: str = "completed"
    started_at: str = ""
    completed_at: str = ""
    duration_seconds: float = 0.0
    output_directory: Path = Path("reports")

    input_path: Path | None = None
    output_path: Path | None = None


class ReportCommandService:
    """Generate and reload SecureForge security reports."""

    def __init__(
        self,
        *,
        reporting_service: ReportingService | None = None,
    ) -> None:
        self.reporting_service = (
            reporting_service
            if reporting_service is not None
            else ReportingService()
        )

    def build_report(
        self,
        *,
        result: SecurityScanResult,
        configuration: ReportCommandConfiguration,
    ) -> SecurityReport:
        """Build a report from a completed security scan."""
        return self.reporting_service.build(result)

    def generate(
        self,
        *,
        result: SecurityScanResult,
        configuration: ReportCommandConfiguration,
    ) -> Path:
        """Generate JSON and HTML reports from a scan result."""
        output_directory = (
            configuration.output_directory
        )

        self.reporting_service.generate(
            result,
            output_directory,
        )

        return output_directory

    def run(
        self,
        configuration: ReportCommandConfiguration,
    ) -> Path:
        """Render an existing JSON report as HTML."""
        if (
            configuration.input_path is None
            or configuration.output_path is None
        ):
            raise ValueError(
                "input_path and output_path are required "
                "for report rendering."
            )

        report = self.reporting_service.load(
            configuration.input_path
        )

        output_path = configuration.output_path
        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.reporting_service.write_html(
            report,
            output_path,
        )

        return output_path


def build_report_command_service() -> ReportCommandService:
    """Build the default report command service."""
    return ReportCommandService()


__all__ = [
    "ReportCommandConfiguration",
    "ReportCommandService",
    "build_report_command_service",
]
