```python id="c2n8wf"
"""Tests for SecureForge scan command services."""

from pathlib import Path

import pytest

from secureforge.cli.scan import (
    ScanCommandConfiguration,
    ScanCommandService,
)
from secureforge.config.runtime_builder import (
    RuntimeConfigurationError,
)
from secureforge.core.config.models import ScanProfile


class FakeScanOrchestrator:
    """Minimal orchestrator used by scan-command tests."""

    def __init__(
        self,
        result,
    ) -> None:
        self.result = result
        self.calls: list[dict[str, object]] = []

    def run(
        self,
        *,
        scan_id: str,
        profile: str,
        target: str,
        source_path: str | None = None,
    ):
        self.calls.append(
            {
                "scan_id": scan_id,
                "profile": profile,
                "target": target,
                "source_path": source_path,
            }
        )

        return self.result


class FakeReportingService:
    """Minimal reporting service used by scan-command tests."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def build_from_scan_result(
        self,
        *,
        result,
        release,
        scan,
        generated_at=None,
    ):
        self.calls.append(
            {
                "result": result,
                "release": release,
                "scan": scan,
                "generated_at": generated_at,
            }
        )

        return "report"

    def generate(
        self,
        report,
        paths,
    ):
        self.calls.append(
            {
                "report": report,
                "paths": paths,
            }
        )

        return paths


def test_scan_command_service_runs_scan(
    sample_scan_result,
    tmp_path: Path,
) -> None:
    """Execute a scan with the supplied configuration."""
    orchestrator = FakeScanOrchestrator(
        sample_scan_result
    )

    reporting_service = (
        FakeReportingService()
    )

    service = ScanCommandService(
        orchestrator=orchestrator,
        reporting_service=reporting_service,
    )

    configuration = ScanCommandConfiguration(
        scan_id="scan-001",
        profile=ScanProfile.STANDARD,
        target="http://127.0.0.1:5000",
        source_path=tmp_path,
    )

    result = service.run(
        configuration
    )

    assert result is sample_scan_result

    assert orchestrator.calls == [
        {
            "scan_id": "scan-001",
            "profile": "standard",
            "target": "http://127.0.0.1:5000",
            "source_path": str(tmp_path),
        }
    ]

    assert len(
        reporting_service.calls
    ) == 2


def test_scan_command_service_rejects_empty_scan_id(
    sample_scan_result,
) -> None:
    """Reject an empty scan identifier."""
    service = ScanCommandService(
        orchestrator=FakeScanOrchestrator(
            sample_scan_result
        ),
        reporting_service=FakeReportingService(),
    )

    configuration = ScanCommandConfiguration(
        scan_id=" ",
        profile=ScanProfile.STANDARD,
        target="http://127.0.0.1:5000",
    )

    with pytest.raises(
        RuntimeConfigurationError,
        match="Scan ID must not be empty",
    ):
        service.run(configuration)


def test_scan_command_service_rejects_empty_target(
    sample_scan_result,
) -> None:
    """Reject an empty scan target."""
    service = ScanCommandService(
        orchestrator=FakeScanOrchestrator(
            sample_scan_result
        ),
        reporting_service=FakeReportingService(),
    )

    configuration = ScanCommandConfiguration(
        scan_id="scan-002",
        profile=ScanProfile.STANDARD,
        target=" ",
    )

    with pytest.raises(
        RuntimeConfigurationError,
        match="Scan target must not be empty",
    ):
        service.run(configuration)


def test_scan_command_service_rejects_missing_source_path(
    sample_scan_result,
    tmp_path: Path,
) -> None:
    """Reject a source path that does not exist."""
    service = ScanCommandService(
        orchestrator=FakeScanOrchestrator(
            sample_scan_result
        ),
        reporting_service=FakeReportingService(),
    )

    missing_path = (
        tmp_path
        / "missing-source"
    )

    configuration = ScanCommandConfiguration(
        scan_id="scan-003",
        profile=ScanProfile.QUICK,
        target="http://127.0.0.1:5000",
        source_path=missing_path,
    )

    with pytest.raises(
        RuntimeConfigurationError,
        match="Source path does not exist",
    ):
        service.run(configuration)


def test_scan_command_service_uses_custom_metadata(
    sample_scan_result,
    tmp_path: Path,
) -> None:
    """Pass release and scan metadata into the reporting layer."""
    orchestrator = FakeScanOrchestrator(
        sample_scan_result
    )

    reporting_service = (
        FakeReportingService()
    )

    service = ScanCommandService(
        orchestrator=orchestrator,
        reporting_service=reporting_service,
    )

    configuration = ScanCommandConfiguration(
        scan_id="scan-004",
        profile=ScanProfile.FULL,
        target="http://127.0.0.1:5000",
        application="securecommerce",
        version="1.0.0",
        commit_sha="abc123",
        environment="lab",
        output_directory=tmp_path,
    )

    service.run(configuration)

    build_call = (
        reporting_service.calls[0]
    )

    release = build_call["release"]
    scan = build_call["scan"]

    assert release.application == "securecommerce"
    assert release.version == "1.0.0"
    assert release.commit_sha == "abc123"
    assert release.environment == "lab"

    assert scan.scan_id == "scan-004"
    assert scan.profile == "full"
```
