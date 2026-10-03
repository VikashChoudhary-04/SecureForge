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
from secureforge.core.scan import (
    ScanResultStore,
)
from secureforge.regression.runner import (
    RegressionRunConfiguration,
)


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
        regression_result=None,
    ):
        self.calls.append(
            {
                "scan_id": scan_id,
                "profile": profile,
                "target": target,
                "source_path": source_path,
            }
        )

        self.regression_result = regression_result

        return self.result


class FakeRegressionRunner:
    """Minimal regression runner used by scan-command tests."""

    def __init__(
        self,
        result,
    ) -> None:
        self.result = result
        self.calls: list[RegressionRunConfiguration] = []

    def run(
        self,
        configuration: RegressionRunConfiguration,
    ):
        self.calls.append(configuration)
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

    scan_store = ScanResultStore(
        directory=tmp_path
    )

    service = ScanCommandService(
        orchestrator=orchestrator,
        reporting_service=reporting_service,
        scan_store=scan_store,
    )

    configuration = ScanCommandConfiguration(
        scan_id="scan-001",
        profile=ScanProfile.STANDARD,
        target="http://127.0.0.1:5000",
        source_path=tmp_path,
        scan_storage_directory=tmp_path,
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

    assert orchestrator.regression_result is None

    assert len(
        reporting_service.calls
    ) == 2

    persisted = scan_store.load(
        "scan-001"
    )

    assert (
        persisted["scan"]["scan_id"]
        == "scan-001"
    )


def test_scan_command_service_persists_to_configured_directory(
    sample_scan_result,
    tmp_path: Path,
) -> None:
    """Persist scans in the directory supplied by the command configuration."""
    orchestrator = FakeScanOrchestrator(
        sample_scan_result
    )

    reporting_service = (
        FakeReportingService()
    )

    default_store_directory = (
        tmp_path
        / "default"
    )

    configured_directory = (
        tmp_path
        / "configured"
    )

    scan_store = ScanResultStore(
        directory=default_store_directory
    )

    service = ScanCommandService(
        orchestrator=orchestrator,
        reporting_service=reporting_service,
        scan_store=scan_store,
    )

    configuration = ScanCommandConfiguration(
        scan_id="scan-002",
        profile=ScanProfile.QUICK,
        target="http://127.0.0.1:5000",
        scan_storage_directory=(
            configured_directory
        ),
    )

    service.run(
        configuration
    )

    assert (
        configured_directory
        / "scan-002.json"
    ).exists()

    assert not (
        default_store_directory
        / "scan-002.json"
    ).exists()


def test_scan_command_service_rejects_empty_scan_id(
    sample_scan_result,
    tmp_path: Path,
) -> None:
    """Reject an empty scan identifier."""
    service = ScanCommandService(
        orchestrator=FakeScanOrchestrator(
            sample_scan_result
        ),
        reporting_service=FakeReportingService(),
        scan_store=ScanResultStore(
            directory=tmp_path
        ),
    )

    configuration = ScanCommandConfiguration(
        scan_id=" ",
        profile=ScanProfile.STANDARD,
        target="http://127.0.0.1:5000",
        scan_storage_directory=tmp_path,
    )

    with pytest.raises(
        RuntimeConfigurationError,
        match="Scan ID must not be empty",
    ):
        service.run(configuration)


def test_scan_command_service_rejects_empty_target(
    sample_scan_result,
    tmp_path: Path,
) -> None:
    """Reject an empty scan target."""
    service = ScanCommandService(
        orchestrator=FakeScanOrchestrator(
            sample_scan_result
        ),
        reporting_service=FakeReportingService(),
        scan_store=ScanResultStore(
            directory=tmp_path
        ),
    )

    configuration = ScanCommandConfiguration(
        scan_id="scan-003",
        profile=ScanProfile.STANDARD,
        target=" ",
        scan_storage_directory=tmp_path,
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
        scan_store=ScanResultStore(
            directory=tmp_path
        ),
    )

    missing_path = (
        tmp_path
        / "missing-source"
    )

    configuration = ScanCommandConfiguration(
        scan_id="scan-004",
        profile=ScanProfile.QUICK,
        target="http://127.0.0.1:5000",
        source_path=missing_path,
        scan_storage_directory=tmp_path,
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
        scan_store=ScanResultStore(
            directory=tmp_path
        ),
    )

    configuration = ScanCommandConfiguration(
        scan_id="scan-005",
        profile=ScanProfile.FULL,
        target="http://127.0.0.1:5000",
        application="securecommerce",
        version="1.0.0",
        commit_sha="abc123",
        environment="lab",
        output_directory=tmp_path,
        scan_storage_directory=tmp_path / "scans",
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

    assert scan.scan_id == "scan-005"
    assert scan.profile == "full"


def test_scan_command_service_runs_regression_and_passes_result_to_orchestrator(
    sample_scan_result,
    tmp_path: Path,
) -> None:
    """Execute regression tests and pass their result into orchestration."""
    suite_path = (
        tmp_path
        / "regression-tests.yaml"
    )
    suite_path.write_text(
        "suite:\n"
        "  id: test-suite\n",
        encoding="utf-8",
    )

    regression_result = object()

    orchestrator = FakeScanOrchestrator(
        sample_scan_result
    )

    regression_runner = FakeRegressionRunner(
        regression_result
    )

    service = ScanCommandService(
        orchestrator=orchestrator,
        reporting_service=FakeReportingService(),
        scan_store=ScanResultStore(
            directory=tmp_path
        ),
        regression_runner=regression_runner,
    )

    configuration = ScanCommandConfiguration(
        scan_id="scan-regression-001",
        profile=ScanProfile.STANDARD,
        target="http://127.0.0.1:5000",
        source_path=tmp_path,
        scan_storage_directory=tmp_path,
        run_regression=True,
        regression_suite_path=suite_path,
    )

    result = service.run(configuration)

    assert result is sample_scan_result

    assert len(
        regression_runner.calls
    ) == 1

    regression_configuration = (
        regression_runner.calls[0]
    )

    assert (
        regression_configuration.suite_path
        == suite_path
    )

    assert (
        regression_configuration.base_url
        == "http://127.0.0.1:5000"
    )

    assert (
        regression_configuration.timeout
        == 5.0
    )

    assert (
        regression_configuration.source_root
        == tmp_path
    )

    assert (
        regression_configuration.infrastructure_root
        is None
    )

    assert (
        orchestrator.regression_result
        is regression_result
    )


def test_scan_command_service_uses_explicit_regression_configuration(
    sample_scan_result,
    tmp_path: Path,
) -> None:
    """Use explicit regression settings when supplied."""
    suite_path = (
        tmp_path
        / "custom-suite.yaml"
    )
    suite_path.write_text(
        "suite:\n"
        "  id: custom-suite\n",
        encoding="utf-8",
    )

    source_root = (
        tmp_path
        / "source"
    )
    source_root.mkdir()

    infrastructure_root = (
        tmp_path
        / "infra"
    )
    infrastructure_root.mkdir()

    regression_result = object()

    orchestrator = FakeScanOrchestrator(
        sample_scan_result
    )

    regression_runner = FakeRegressionRunner(
        regression_result
    )

    service = ScanCommandService(
        orchestrator=orchestrator,
        reporting_service=FakeReportingService(),
        scan_store=ScanResultStore(
            directory=tmp_path
        ),
        regression_runner=regression_runner,
    )

    configuration = ScanCommandConfiguration(
        scan_id="scan-regression-002",
        profile=ScanProfile.FULL,
        target="http://127.0.0.1:5000",
        scan_storage_directory=tmp_path,
        run_regression=True,
        regression_suite_path=suite_path,
        regression_base_url="http://127.0.0.1:6000",
        regression_timeout=10.0,
        regression_source_root=source_root,
        regression_infrastructure_root=(
            infrastructure_root
        ),
    )

    service.run(configuration)

    regression_configuration = (
        regression_runner.calls[0]
    )

    assert (
        regression_configuration.suite_path
        == suite_path
    )

    assert (
        regression_configuration.base_url
        == "http://127.0.0.1:6000"
    )

    assert (
        regression_configuration.timeout
        == 10.0
    )

    assert (
        regression_configuration.source_root
        == source_root
    )

    assert (
        regression_configuration.infrastructure_root
        == infrastructure_root
    )

    assert (
        orchestrator.regression_result
        is regression_result
    )


def test_scan_command_service_rejects_missing_regression_suite(
    sample_scan_result,
    tmp_path: Path,
) -> None:
    """Reject an enabled regression run when its suite is missing."""
    missing_suite = (
        tmp_path
        / "missing-regression.yaml"
    )

    service = ScanCommandService(
        orchestrator=FakeScanOrchestrator(
            sample_scan_result
        ),
        reporting_service=FakeReportingService(),
        scan_store=ScanResultStore(
            directory=tmp_path
        ),
        regression_runner=FakeRegressionRunner(
            object()
        ),
    )

    configuration = ScanCommandConfiguration(
        scan_id="scan-regression-003",
        profile=ScanProfile.STANDARD,
        target="http://127.0.0.1:5000",
        scan_storage_directory=tmp_path,
        run_regression=True,
        regression_suite_path=missing_suite,
    )

    with pytest.raises(
        RuntimeConfigurationError,
        match="Regression configuration not found",
    ):
        service.run(configuration)


def test_scan_command_service_rejects_invalid_regression_timeout(
    sample_scan_result,
    tmp_path: Path,
) -> None:
    """Reject a non-positive regression timeout."""
    suite_path = (
        tmp_path
        / "regression-tests.yaml"
    )
    suite_path.write_text(
        "suite:\n"
        "  id: test-suite\n",
        encoding="utf-8",
    )

    service = ScanCommandService(
        orchestrator=FakeScanOrchestrator(
            sample_scan_result
        ),
        reporting_service=FakeReportingService(),
        scan_store=ScanResultStore(
            directory=tmp_path
        ),
        regression_runner=FakeRegressionRunner(
            object()
        ),
    )

    configuration = ScanCommandConfiguration(
        scan_id="scan-regression-004",
        profile=ScanProfile.STANDARD,
        target="http://127.0.0.1:5000",
        scan_storage_directory=tmp_path,
        run_regression=True,
        regression_suite_path=suite_path,
        regression_timeout=0,
    )

    with pytest.raises(
        RuntimeConfigurationError,
        match="Regression timeout must be greater than zero",
    ):
        service.run(configuration)
