```python id="n6v4xr"
"""SecureForge scan command service."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from datetime import datetime

from secureforge.config.runtime_builder import (
    RuntimeConfigurationError,
)
from secureforge.core.config.models import ScanProfile
from secureforge.core.scan import (
    ScanOrchestrator,
    ScanResultStore,
    ScanRunner,
    SecurityScanResult,
)
from secureforge.integrations.registry_factory import (
    build_default_integration_registry,
)
from secureforge.reporting import (
    ReleaseMetadata,
    ReportPaths,
    ScanMetadata,
    SecurityReportService,
)


@dataclass(frozen=True)
class ScanCommandConfiguration:
    """Configuration supplied to the SecureForge scan command."""

    scan_id: str
    profile: ScanProfile
    target: str
    source_path: Path | None = None
    application: str = "secureforge-target"
    version: str = "unknown"
    commit_sha: str = "unknown"
    environment: str = "local"
    output_directory: Path = Path("reports")
    scan_storage_directory: Path = Path(
        "reports/scans"
    )


class ScanCommandService:
    """Execute SecureForge scans and persist their results."""

    def __init__(
        self,
        *,
        orchestrator: ScanOrchestrator | None = None,
        reporting_service: SecurityReportService | None = None,
        scan_store: ScanResultStore | None = None,
    ) -> None:
        if orchestrator is not None:
            self.orchestrator = orchestrator
        else:
            registry = (
                build_default_integration_registry()
            )

            runner = ScanRunner(
                registry=registry
            )

            self.orchestrator = ScanOrchestrator(
                runner=runner
            )

        self.reporting_service = (
            reporting_service
            if reporting_service is not None
            else SecurityReportService()
        )

        self.scan_store = (
            scan_store
            if scan_store is not None
            else ScanResultStore()
        )

    def run(
        self,
        configuration: ScanCommandConfiguration,
    ) -> SecurityScanResult:
        """Execute, persist, and report a configured security scan."""
        self._validate_configuration(
            configuration
        )

        result = self.orchestrator.run(
            scan_id=configuration.scan_id,
            profile=configuration.profile.value,
            target=configuration.target,
            source_path=(
                str(configuration.source_path)
                if configuration.source_path is not None
                else None
            ),
        )

        self._persist_scan_result(
            result=result,
            configuration=configuration,
        )

        self._generate_reports(
            result=result,
            configuration=configuration,
        )

        return result

    def _persist_scan_result(
        self,
        *,
        result: SecurityScanResult,
        configuration: ScanCommandConfiguration,
    ) -> Path:
        """Persist the complete scan result."""
        store = (
            self.scan_store
            if configuration.scan_storage_directory
            == self.scan_store.directory
            else ScanResultStore(
                directory=(
                    configuration.scan_storage_directory
                )
            )
        )

        return store.save(
            result,
            scan_id=configuration.scan_id,
        )

    def _generate_reports(
        self,
        *,
        result: SecurityScanResult,
        configuration: ScanCommandConfiguration,
    ) -> ReportPaths:
        """Generate JSON and HTML reports for a completed scan."""
        started_at = (
            result.execution.started_at
            or ""
        )

        completed_at = (
            result.execution.completed_at
            or ""
        )

        duration_seconds = 0.0

        if (
            result.execution.started_at
            and result.execution.completed_at
        ):
            started = datetime.fromisoformat(
                result.execution.started_at
            )
            completed = datetime.fromisoformat(
                result.execution.completed_at
            )

            duration_seconds = max(
                (
                    completed - started
                ).total_seconds(),
                0.0,
            )

        release = ReleaseMetadata(
            release_id=configuration.scan_id,
            application=configuration.application,
            version=configuration.version,
            commit_sha=configuration.commit_sha,
            environment=configuration.environment,
            timestamp=completed_at,
        )

        scan = ScanMetadata(
            scan_id=configuration.scan_id,
            profile=configuration.profile.value,
            status=result.execution.status.value,
            tools=list(
                result.execution.tools
            ),
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration_seconds,
        )

        report = (
            self.reporting_service.build_from_scan_result(
                result=result,
                release=release,
                scan=scan,
            )
        )

        paths = ReportPaths(
            json_path=(
                configuration.output_directory
                / "security-report.json"
            ),
            html_path=(
                configuration.output_directory
                / "security-report.html"
            ),
        )

        return self.reporting_service.generate(
            report,
            paths,
        )

    @staticmethod
    def _validate_configuration(
        configuration: ScanCommandConfiguration,
    ) -> None:
        """Validate scan command configuration."""
        if not configuration.scan_id.strip():
            raise RuntimeConfigurationError(
                "Scan ID must not be empty."
            )

        if not configuration.target.strip():
            raise RuntimeConfigurationError(
                "Scan target must not be empty."
            )

        if (
            configuration.source_path is not None
            and not configuration.source_path.exists()
        ):
            raise RuntimeConfigurationError(
                "Source path does not exist: "
                f"{configuration.source_path}"
            )


def build_scan_command_service() -> ScanCommandService:
    """Build the default scan command service."""
    return ScanCommandService()
```
