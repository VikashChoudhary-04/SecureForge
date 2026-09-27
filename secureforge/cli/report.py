```python id="r8m2kx"
"""SecureForge report command service."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from secureforge.core.scan.orchestrator import (
    SecurityScanResult,
)
from secureforge.reporting import (
    ReleaseMetadata,
    ReportPaths,
    ScanMetadata,
    SecurityReport,
    SecurityReportLoadError,
    SecurityReportLoader,
    SecurityReportService,
)


@dataclass(frozen=True)
class ReportCommandConfiguration:
    """Configuration supplied to the SecureForge report command."""

    release_id: str
    application: str
    version: str
    commit_sha: str
    environment: str
    scan_id: str
    profile: str
    scan_status: str
    started_at: str
    completed_at: str
    duration_seconds: float
    output_directory: Path = Path("reports")


class ReportCommandService:
    """Generate and reload SecureForge security reports."""

    def __init__(
        self,
        *,
        reporting_service: SecurityReportService | None = None,
        report_loader: SecurityReportLoader | None = None,
    ) -> None:
        self.reporting_service = (
            reporting_service
            if reporting_service is not None
            else SecurityReportService()
        )

        self.report_loader = (
            report_loader
            if report_loader is not None
            else SecurityReportLoader()
        )

    def build_report(
        self,
        *,
        result: SecurityScanResult,
        configuration: ReportCommandConfiguration,
    ) -> SecurityReport:
        """Build a report from a completed security scan."""
        release = ReleaseMetadata(
            release_id=configuration.release_id,
            application=configuration.application,
            version=configuration.version,
            commit_sha=configuration.commit_sha,
            environment=configuration.environment,
            timestamp=configuration.completed_at,
        )

        scan = ScanMetadata(
            scan_id=configuration.scan_id,
            profile=configuration.profile,
            status=configuration.scan_status,
            tools=[],
            started_at=configuration.started_at,
            completed_at=configuration.completed_at,
            duration_seconds=(
                configuration.duration_seconds
            ),
        )

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
    ) -> ReportPaths:
        """Generate JSON and HTML reports from a scan result."""
        report = self.build_report(
            result=result,
            configuration=configuration,
        )

        output_directory = (
            configuration.output_directory
        )

        paths = ReportPaths(
            json_path=(
                output_directory
                / "security-report.json"
            ),
            html_path=(
                output_directory
                / "security-report.html"
            ),
        )

        return self.reporting_service.generate(
            report,
            paths,
        )

    def load(
        self,
        path: Path,
    ) -> SecurityReport:
        """Load and validate an existing security report."""
        try:
            return self.report_loader.load(path)
        except SecurityReportLoadError:
            raise

    def regenerate_html(
        self,
        *,
        json_path: Path,
        html_path: Path | None = None,
    ) -> Path:
        """Regenerate an HTML report from persisted JSON."""
        report = self.load(json_path)

        output_path = (
            html_path
            if html_path is not None
            else json_path.with_suffix(".html")
        )

        self.reporting_service.renderer.write_html(
            report,
            output_path,
        )

        return output_path


def build_report_command_service() -> ReportCommandService:
    """Build the default report command service."""
    return ReportCommandService()
```
