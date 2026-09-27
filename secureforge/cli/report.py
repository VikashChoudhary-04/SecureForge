"""SecureForge report command service."""

from **future** import annotations

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
SecurityReportService,
)

@dataclass(frozen=True)
class ReportCommandConfiguration:
"""Configuration supplied to the SecureForge report command."""

```
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
```

class ReportCommandService:
"""Generate SecureForge reports from completed scan results."""

```
def __init__(
    self,
    *,
    reporting_service: SecurityReportService | None = None,
) -> None:
    self.reporting_service = (
        reporting_service
        if reporting_service is not None
        else SecurityReportService()
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
```

def build_report_command_service() -> ReportCommandService:
"""Build the default report command service."""
return ReportCommandService()
