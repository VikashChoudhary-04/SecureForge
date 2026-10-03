from __future__ import annotations

from dataclasses import dataclass
import inspect
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
from secureforge.regression.runner import (
    RegressionRunConfiguration,
    RegressionRunner,
)
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
    regression_suite_path: Path = Path(
        "requirements/regression-tests.yaml"
    )
    regression_base_url: str | None = None
    regression_timeout: float = 5.0
    regression_source_root: Path | None = None
    regression_infrastructure_root: Path | None = None


class ScanCommandService:
    """Execute scans and persist their results."""

    def __init__(
        self,
        *,
        orchestrator: ScanOrchestrator,
        scan_store: ScanResultStore,
        reporting_service: ReportingService | None = None,
        regression_runner: RegressionRunner | None = None,
    ) -> None:
        self.orchestrator = orchestrator
        self.scan_store = scan_store
        self.reporting_service = (
            reporting_service
            if reporting_service is not None
            else ReportingService()
        )
        self.regression_runner = (
            regression_runner
            if regression_runner is not None
            else RegressionRunner()
        )

    def run(
        self,
        configuration: ScanCommandConfiguration,
    ) -> SecurityScanResult:
        """Execute and persist a configured scan."""
        self._validate_configuration(configuration)

        profile = (
            configuration.profile.value
            if isinstance(configuration.profile, ScanProfile)
            else str(configuration.profile)
        )

        regression_result = None

        if configuration.run_regression:
            regression_result = self._run_regression(
                configuration=configuration,
            )

        orchestrator_arguments = {
            "scan_id": configuration.scan_id.strip(),
            "profile": profile,
            "target": (
                configuration.target.strip()
                if configuration.target is not None
                else None
            ),
            "source_path": (
                str(configuration.source_path)
                if configuration.source_path is not None
                else None
            ),
            "application": configuration.application,
            "version": configuration.version,
            "commit_sha": configuration.commit_sha,
            "environment": configuration.environment,
            "validation_requests": (
                list(configuration.validation_requests)
                if configuration.validation_requests
                else None
            ),
            "validate_findings": configuration.validate_findings,
            "validation_method": configuration.validation_method,
            "run_regression": configuration.run_regression,
            "regression_result": regression_result,
        }

        signature = inspect.signature(self.orchestrator.run)
        parameters = signature.parameters.values()
        accepts_kwargs = any(
            parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in parameters
        )

        if not accepts_kwargs:
            orchestrator_arguments = {
                name: value
                for name, value in orchestrator_arguments.items()
                if name in signature.parameters
            }

        result = self.orchestrator.run(
            **orchestrator_arguments
        )

        self._persist_result(
            result=result,
            configuration=configuration,
        )

        return result

    def _run_regression(
        self,
        *,
        configuration: ScanCommandConfiguration,
    ):
        """Execute the configured regression suite."""
        base_url = (
            configuration.regression_base_url
            or configuration.target
        )

        if base_url is None or not base_url.strip():
            raise RuntimeConfigurationError(
                "Regression base URL must not be empty."
            )

        source_root = (
            configuration.regression_source_root
            if configuration.regression_source_root is not None
            else configuration.source_path
        )

        regression_configuration = RegressionRunConfiguration(
            suite_path=configuration.regression_suite_path,
            base_url=base_url.strip(),
            timeout=configuration.regression_timeout,
            source_root=source_root,
            infrastructure_root=(
                configuration.regression_infrastructure_root
            ),
        )

        return self.regression_runner.run(
            regression_configuration
        )

    def _validate_configuration(
        self,
        configuration: ScanCommandConfiguration,
    ) -> None:
        """Validate command-level scan configuration."""
        if not configuration.scan_id.strip():
            raise RuntimeConfigurationError(
                "Scan ID must not be empty."
            )

        profile = (
            configuration.profile.value
            if isinstance(configuration.profile, ScanProfile)
            else str(configuration.profile)
        )
        is_ci_profile = profile.strip().lower() == "ci"

        if not is_ci_profile:
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

        if configuration.regression_timeout <= 0:
            raise RuntimeConfigurationError(
                "Regression timeout must be greater than zero."
            )

        if configuration.run_regression:
            if not configuration.regression_suite_path.is_file():
                raise RuntimeConfigurationError(
                    "Regression configuration not found: "
                    f"{configuration.regression_suite_path}"
                )

            if (
                configuration.regression_source_root is not None
                and not configuration.regression_source_root.is_dir()
            ):
                raise RuntimeConfigurationError(
                    "Regression source root must be a directory: "
                    f"{configuration.regression_source_root}"
                )

            if (
                configuration.regression_infrastructure_root
                is not None
                and not configuration.regression_infrastructure_root.is_dir()
            ):
                raise RuntimeConfigurationError(
                    "Regression infrastructure root must be a directory: "
                    f"{configuration.regression_infrastructure_root}"
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
            result,
            scan_id=configuration.scan_id.strip(),
        )

        report_configuration = ReportCommandConfiguration(
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
                else str(configuration.profile)
            ),
            output_directory=configuration.output_directory,
        )

        report_service = ReportCommandService(
            reporting_service=self.reporting_service
        )

        report_service.generate(
            result=result,
            configuration=report_configuration,
        )


ScanCommandConfig = ScanCommandConfiguration


def build_scan_command_service() -> ScanCommandService:
    """Build the default scan command service."""
    from secureforge.config.runtime import build_runtime

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
