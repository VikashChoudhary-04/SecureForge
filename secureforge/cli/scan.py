```python id="6p2r8m"
"""Scan service used by the SecureForge CLI."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from secureforge.core.scan.models import SecurityScanResult
from secureforge.core.scan.orchestrator import ScanOrchestrator
from secureforge.core.scan.store import ScanResultStore
from secureforge.validation.models import ValidationRequest


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
    run_regression: bool = False


class ScanCommandService:
    """Execute scans and persist their results."""

    def __init__(
        self,
        *,
        orchestrator: ScanOrchestrator,
        store: ScanResultStore,
    ) -> None:
        self.orchestrator = orchestrator
        self.store = store

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
        """Persist the scan result and generate report artifacts."""
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

        self._write_json_report(
            result=result,
            output_directory=config.output_directory,
        )

        self._write_html_report(
            result=result,
            output_directory=config.output_directory,
        )

    @staticmethod
    def _write_json_report(
        *,
        result: SecurityScanResult,
        output_directory: Path,
    ) -> Path:
        """Write the complete scan result as JSON."""
        import json

        output_path = output_directory / "security-report.json"

        output_path.write_text(
            json.dumps(
                result.pipeline.to_dict(),
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )

        return output_path

    @staticmethod
    def _write_html_report(
        *,
        result: SecurityScanResult,
        output_directory: Path,
    ) -> Path:
        """Write an HTML representation of the scan result."""
        from secureforge.reporting.html import HTMLReportRenderer

        output_path = output_directory / "security-report.html"

        renderer = HTMLReportRenderer()
        html = renderer.render(
            result.pipeline.to_dict()
        )

        output_path.write_text(
            html,
            encoding="utf-8",
        )

        return output_path
```
