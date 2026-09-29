"""Scan service used by the SecureForge CLI."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from secureforge.cli.report import (
    ReportCommandConfiguration,
    ReportCommandService,
)
from secureforge.config.runtime_builder import (
    RuntimeConfigurationError,
)
from secureforge.core.config.models import ScanProfile
from secureforge.core.scan.models import SecurityScanResult
from secureforge.core.scan.orchestrator import ScanOrchestrator
from secureforge.core.scan.store import ScanResultStore
from secureforge.reporting.service import ReportingService
from secureforge.validation.models import (
    ValidationMethod,
    ValidationRequest,
)


@dataclass(frozen=True)
class ScanCommandConfiguration:
    """Configuration for a SecureForge scan command."""

    scan_id: str
    profile: ScanProfile | str
    target: str | None = None
    source_path: Path | None = None
    application: str = "securecommerce"
    version: str = "unknown"
    commit_sha: str | None = None
    environment: str = "lab"
    output_directory: Path = Path("reports")
    scan_storage_directory: Path = Path("scans")
    validation_requests: tuple[ValidationRequest, ...] = ()
    validate_findings: bool = False
    validation_method: ValidationMethod = ValidationMethod.HTTP
    run_regression: bool = False


class ScanCommandService:
    """Execute scans and persist their results."""

    def __init__(
        self,
        *,
        orchestrator: ScanOrchestrator,
        scan_store: ScanResultStore,
        reporting_service: ReportingService | None = None,
    ) -> None:
        self.orchestrator = orchestrator
        self.scan_store = scan_store
        self.reporting_service = (
            reporting_service
            if reporting_service is not None
            else ReportingService()
        )

    def run(
        self,
        configuration: ScanCommandConfiguration,
    ) -> SecurityScanResult:
        """Execute and persist a configured scan."""
        self._validate_configuration(
            configuration
        )

        profile = (
            configuration.profile.value
            if isinstance(
                configuration.profile,
                ScanProfile,
            )
            else str(
                configuration.profile
            )
        )

        result = self.orchestrator.run(
            scan_id=configuration.scan_id.strip(),
            profile=profile,
            target=configuration.target.strip(),
            source_path=configuration.source_path,
            application=configuration.application,
            version=configuration.version,
            commit_sha=configuration.commit_sha,
            environment=configuration.environment,
            validation_requests=(
                list(
                    configuration.validation_requests
                )
                if configuration.validation_requests
                else None
            ),
            validate_findings=(
                configuration.validate_findings
            ),
            validation_method=(
                configuration.validation_method
            ),
            run_regression=(
                configuration.run_regression
            ),
        )

        self._persist_result(
            result=result,
            configuration=configuration,
        )

        return result

    def _validate_configuration(
        self,
        configuration: ScanCommandConfiguration,
    ) -> None:
        """Validate command-level scan configuration."""
        if not configuration.scan_id.strip():
            raise RuntimeConfigurationError(
                "Scan ID must not be empty."
            )

        if (
            configuration.target is None
            or not configuration.target.strip()
        ):
            raise RuntimeConfigurationError(
                "Scan target must not be empty."
            )

        if configuration.source_path is not None:
            if not configuration.source_path.exists():
                raise RuntimeConfigurationError(
                    "Source path does not exist: "
                    f"{configuration.source_path}"
                )

            if not configuration.source_path.is_dir():
                raise RuntimeConfigurationError(
                    "Source path must be a directory: "
                    f"{configuration.source_path}"
                )

    def _persist_result(
        self,
        *,
        result: SecurityScanResult,
        configuration: ScanCommandConfiguration,
    ) -> None:
        """Persist scan data and generate security reports."""
        configuration.scan_storage_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        configuration.output_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.scan_store.directory = (
            configuration.scan_storage_directory
        )

        self.scan_store.save(
            result
        )

        report_configuration = (
            ReportCommandConfiguration(
                release_id=configuration.scan_id,
                application=configuration.application,
                version=configuration.version,
                commit_sha=(
                    configuration.commit_sha
                    or "unknown"
                ),
                environment=configuration.environment,
                scan_id=configuration.scan_id,
                profile=(
                    configuration.profile.value
                    if isinstance(
                        configuration.profile,
                        ScanProfile,
                    )
                    else str(
                        configuration.profile
                    )
                ),
                output_directory=(
                    configuration.output_directory
                ),
            )
        )

        report_service = ReportCommandService(
            reporting_service=(
                self.reporting_service
            )
        )

        report_service.generate(
            result=result,
            configuration=report_configuration,
        )


ScanCommandConfig = ScanCommandConfiguration


def build_scan_command_service() -> ScanCommandService:
    """Build the default scan command service."""
    from secureforge.config.runtime import (
        build_runtime,
    )

    runtime = build_runtime()

    return ScanCommandService(
        orchestrator=runtime.orchestrator,
        scan_store=runtime.store,
        reporting_service=ReportingService(),
    )


__all__ = [
    "ScanCommandConfig",
    "ScanCommandConfiguration",
    "ScanCommandService",
    "build_scan_command_service",
]
