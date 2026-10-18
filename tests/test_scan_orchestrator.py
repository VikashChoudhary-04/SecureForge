"""Tests for SecureForge scan orchestration."""

from secureforge.core.config.models import (
    ScanConfiguration,
    ScanProfile,
    TargetConfiguration,
    ToolConfiguration,
)
from secureforge.core.scan.orchestrator import (
    ScanOrchestrator,
)


def test_scan_orchestrator_runs_scan(
    fake_scan_runner,
) -> None:
    """Run a scan and produce a complete security result."""
    orchestrator = ScanOrchestrator(
        runner=fake_scan_runner
    )

    result = orchestrator.run(
        scan_id="scan-001",
        profile="standard",
        target="http://localhost:5000",
    )

    assert result.execution.scan_id == "scan-001"
    assert result.execution.profile == "standard"
    assert result.execution.target == (
        "http://localhost:5000"
    )

    assert result.findings
    assert result.pipeline is not None
    assert result.pipeline.risk is not None
    assert result.pipeline.policy is not None
    assert result.pipeline.release_gate is not None


def test_scan_orchestrator_populates_result_summary(
    fake_scan_runner,
) -> None:
    """Populate the final result summary from the executed scan."""
    orchestrator = ScanOrchestrator(
        runner=fake_scan_runner
    )

    result = orchestrator.run(
        scan_id="scan-summary-001",
        profile="standard",
        target="http://localhost:5000",
    )

    assert result.summary.finding_count == len(
        result.findings
    )

    assert result.summary.high_findings == sum(
        finding.severity.value == "high"
        for finding in result.findings
    )

    assert result.summary.medium_findings == sum(
        finding.severity.value == "medium"
        for finding in result.findings
    )

    assert result.summary.low_findings == sum(
        finding.severity.value == "low"
        for finding in result.findings
    )

    assert result.summary.info_findings == sum(
        finding.severity.value in {
            "info",
            "informational",
        }
        for finding in result.findings
    )


def test_scan_orchestrator_exposes_release_status(
    fake_scan_runner,
) -> None:
    """Expose the final release decision from the pipeline."""
    orchestrator = ScanOrchestrator(
        runner=fake_scan_runner
    )

    result = orchestrator.run(
        scan_id="scan-002",
        profile="quick",
        target="http://localhost:5000",
    )

    assert result.release_allowed == (
        result.pipeline.release_allowed
    )

    assert result.release_blocked == (
        result.pipeline.release_blocked
    )

    assert result.release_status == (
        result.pipeline.release_gate.status.value
    )


def test_scan_orchestrator_serializes_complete_result(
    fake_scan_runner,
) -> None:
    """Serialize the complete scan result."""
    orchestrator = ScanOrchestrator(
        runner=fake_scan_runner
    )

    result = orchestrator.run(
        scan_id="scan-003",
        profile="standard",
        target="http://localhost:5000",
    )

    payload = result.to_dict()

    assert isinstance(
        payload,
        dict,
    )

    assert "scan" in payload
    assert "findings" in payload
    assert "pipeline" in payload

    assert payload["scan"]["scan_id"] == (
        "scan-003"
    )

    assert isinstance(
        payload["findings"],
        list,
    )

    assert isinstance(
        payload["pipeline"],
        dict,
    )


def test_scan_orchestrator_passes_source_path(
    fake_scan_runner,
) -> None:
    """Pass source-code context to the scan runner."""
    orchestrator = ScanOrchestrator(
        runner=fake_scan_runner
    )

    result = orchestrator.run(
        scan_id="scan-004",
        profile="quick",
        target="http://localhost:5000",
        source_path="/workspace/securecommerce",
    )

    assert result.execution.scan_id == "scan-004"

    assert fake_scan_runner.last_source_path == (
        "/workspace/securecommerce"
    )


def test_scan_orchestrator_accepts_regression_result(
    fake_scan_runner,
    sample_regression_result,
) -> None:
    """Pass regression results into the security pipeline."""
    orchestrator = ScanOrchestrator(
        runner=fake_scan_runner
    )

    result = orchestrator.run(
        scan_id="scan-005",
        profile="standard",
        target="http://localhost:5000",
        regression_result=sample_regression_result,
    )

    assert result.pipeline.regression == (
        sample_regression_result
    )


def test_scan_orchestrator_accepts_regression_gate(
    fake_scan_runner,
    sample_regression_gate,
) -> None:
    """Pass regression-gate decisions into the security pipeline."""
    orchestrator = ScanOrchestrator(
        runner=fake_scan_runner
    )

    result = orchestrator.run(
        scan_id="scan-006",
        profile="standard",
        target="http://localhost:5000",
        regression_gate=sample_regression_gate,
    )

    assert result.pipeline.regression_gate == (
        sample_regression_gate
    )


def test_scan_orchestrator_preserves_configured_tools(
) -> None:
    """Preserve configured scanner tools for runner execution."""
    captured = {}

    class CapturingRunner:
        def run(
            self,
            configuration,
            commit_sha=None,
        ):
            captured["configuration"] = configuration

            from secureforge.core.scan.models import ScanRun

            scan = ScanRun(
                scan_id="configured-tool-scan",
                application=configuration.application,
                version=configuration.version,
                profile=configuration.profile,
                environment=configuration.environment,
            )
            scan.start()
            scan.complete()
            return scan

    configured_tool = ToolConfiguration(
        name="nmap",
        enabled=True,
        executable="nmap",
        command=[
            "nmap",
            "-sV",
            "-oX",
            "-",
            "127.0.0.1",
        ],
        timeout_seconds=300,
    )

    scan_configuration = ScanConfiguration(
        application="SecureCommerce",
        version="0.1.0",
        profile=ScanProfile.FULL,
        environment="lab",
        target=TargetConfiguration(
            name="127.0.0.1",
            network_target="127.0.0.1",
        ),
        tools=[
            configured_tool,
        ],
    )

    orchestrator = ScanOrchestrator(
        runner=CapturingRunner()
    )

    orchestrator._run_runner(
        scan_id="configured-tool-scan",
        profile="full",
        target="127.0.0.1",
        source_path=None,
        application="SecureCommerce",
        version="0.1.0",
        commit_sha=None,
        environment="lab",
        risk_context=None,
        configuration=scan_configuration,
    )

    configuration = captured["configuration"]

    assert configuration is scan_configuration
    assert configuration.profile == ScanProfile.FULL
    assert configuration.tools == [
        configured_tool,
    ]
    assert configuration.tools[0].name == "nmap"
