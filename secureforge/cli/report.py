"""SecureForge report command service."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from secureforge.core.scan.models import SecurityScanResult
from secureforge.reporting import (
    ReleaseMetadata,
    ReportPaths,
    ReportingService,
    ScanMetadata,
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

    @staticmethod
    def _build_release_metadata(
        configuration: ReportCommandConfiguration,
        result: SecurityScanResult,
    ) -> ReleaseMetadata:
        """Build release metadata from command configuration and scan decision."""
        decision = result.pipeline.release_gate

        return ReleaseMetadata(
            scan_id=configuration.scan_id,
            release_id=configuration.release_id,
            application=configuration.application,
            version=configuration.version,
            commit_sha=configuration.commit_sha,
            environment=configuration.environment,
            release_allowed=decision.release_allowed,
            release_blocked=not decision.release_allowed,
        )

    @staticmethod
    def _build_scan_metadata(
        configuration: ReportCommandConfiguration,
    ) -> ScanMetadata:
        """Build scan metadata for the reporting layer."""
        return ScanMetadata(
            scan_id=configuration.scan_id,
            profile=configuration.profile,
            application=configuration.application,
            version=configuration.version,
            commit_sha=configuration.commit_sha,
            environment=configuration.environment,
            started_at=configuration.started_at,
            completed_at=configuration.completed_at,
            status=configuration.scan_status,
        )

    @staticmethod
    def _build_report_paths(
        configuration: ReportCommandConfiguration,
    ) -> ReportPaths:
        """Build JSON and HTML output paths."""
        output_directory = configuration.output_directory
        scan_id = configuration.scan_id or "scan"

        return ReportPaths(
            json_path=output_directory / f"{scan_id}.json",
            html_path=output_directory / f"{scan_id}.html",
        )

    def build_report(
        self,
        *,
        result: SecurityScanResult,
        configuration: ReportCommandConfiguration,
    ) -> SecurityReport:
        """Build a report from a completed security scan."""
        release = self._build_release_metadata(
            configuration,
            result,
        )
        scan = self._build_scan_metadata(configuration)

        return self.reporting_service.build_from_scan_result(
            result=result,
            release=release,
            scan=scan,
        )

    def generate(
        self,
        *,
        result: SecurityScanResult,
        configuration: ReportCommandConfiguration,
    ) -> Path:
        """Generate JSON and HTML reports from a scan result."""
        output_directory = configuration.output_directory
        output_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        release = self._build_release_metadata(
            configuration,
            result,
        )
        scan = self._build_scan_metadata(configuration)
        paths = self._build_report_paths(configuration)

        report = self.reporting_service.build_from_scan_result(
            result=result,
            release=release,
            scan=scan,
        )

        self.reporting_service.generate(
            report,
            paths,
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
