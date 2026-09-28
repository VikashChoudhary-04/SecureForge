"""Scan service used by the SecureForge CLI."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from secureforge.core.scan.models import SecurityScanResult
from secureforge.core.scan.orchestrator import ScanOrchestrator
from secureforge.core.scan.store import ScanResultStore
from secureforge.reporting.service import ReportingService
from secureforge.validation.models import (
    ValidationMethod,
    ValidationRequest,
)


@dataclass(frozen=True)
class ScanCommandConfig:
    """Configuration for a SecureForge scan command."""

    scan_id: str
    profile: str
    target: str | None
    source_path: Path | None
    application: str
    version: str
    commit_sha: str | None
    environment: str
    output_directory: Path
    scan_storage_directory: Path
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
        store: ScanResultStore,
        reporting: ReportingService | None = None,
    ) -> None:
        self.orchestrator = orchestrator
        self.store = store
        self.reporting = (
            reporting
            if reporting is not None
            else ReportingService()
        )

    def run(
        self,
        config: ScanCommandConfig,
    ) -> SecurityScanResult:
        """Execute and persist a configured scan."""
        result = self.orchestrator.run(
            scan_id=config.scan_id,
            profile=config.profile,
            target=config.target,
            source_path=config.source_path,
            application=config.application,
            version=config.version,
            commit_sha=config.commit_sha,
            environment=config.environment,
            validation_requests=(
                list(config.validation_requests)
                if config.validation_requests
                else None
            ),
            validate_findings=config.validate_findings,
            validation_method=config.validation_method,
            run_regression=config.run_regression,
        )

        self._persist_result(
            result=result,
            config=config,
        )

        return result

    def _persist_result(
        self,
        *,
        result: SecurityScanResult,
        config: ScanCommandConfig,
    ) -> None:
        """Persist scan data and generate security reports."""
        config.scan_storage_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        config.output_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.store.save(
            result,
            config.scan_storage_directory,
        )

        self.reporting.generate(
            result,
            config.output_directory,
        )
