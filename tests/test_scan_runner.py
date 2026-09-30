"""Tests for the SecureForge scan runner."""

from dataclasses import dataclass
from datetime import datetime, timezone

from secureforge.core.config import (
    ScanConfiguration,
    ScanProfile,
    TargetConfiguration,
    TargetType,
    ToolConfiguration,
)
from secureforge.core.normalization import (
    NormalizationAdapter,
    NormalizationPipeline,
    NormalizationRegistry,
)
from secureforge.core.scan import (
    ScanRunFactory,
    ScanStatus,
    ScanRunner,
    ToolExecutionResult,
    ToolExecutionStatus,
)


class FakeAdapter(NormalizationAdapter):
    """Controlled normalization adapter for runner tests."""

    source_name = "sast"

    def parse(self, raw_evidence):
        """Return a controlled normalized finding."""
        from secureforge.core.normalization import NormalizationResult

        return NormalizationResult(
            source=self.source_name,
            findings=[
                {
                    "title": "SQL Injection",
                    "source": "sast",
                    "application": "SecureCommerce",
                    "asset": "securecommerce-api",
                    "endpoint": "/api/products",
                    "parameter": "search",
                    "cwe": "CWE-89",
                    "severity": "high",
                    "description": "Controlled SQL injection finding.",
                    "impact": "Database queries may be manipulated.",
                    "remediation": "Use parameterized queries.",
                }
            ],
            success=True,
        )


class FailingAdapter(NormalizationAdapter):
    """Controlled normalization adapter that fails."""

    source_name = "sca"

    def parse(self, raw_evidence):
        """Raise a controlled parsing error."""
        raise ValueError("Controlled normalization failure.")


@dataclass
class FakeExecutor:
    """Controlled executor returning predefined results."""

    results: dict[str, ToolExecutionResult]

    def execute(self, tool):
        """Return the configured result for a tool."""
        return self.results[tool.name]


def build_configuration(
    *,
    profile: ScanProfile = ScanProfile.QUICK,
    tools: list[ToolConfiguration] | None = None,
) -> ScanConfiguration:
    """Create a representative SecureForge configuration."""
    return ScanConfiguration(
        application="SecureCommerce",
        version="1.0.0",
        profile=profile,
        environment="lab",
        target=TargetConfiguration(
            name="securecommerce-local",
            target_type=TargetType.WEB_AND_API,
            base_url="http://localhost:5000",
            api_base_url="http://localhost:5000/api",
            openapi_url="http://localhost:5000/openapi.json",
        ),
        tools=tools or [],
    )


def build_result(
    tool_name: str,
    *,
    status: ToolExecutionStatus = ToolExecutionStatus.SUCCESS,
) -> ToolExecutionResult:
    """Create a controlled tool execution result."""
    timestamp = datetime.now(timezone.utc)

    return ToolExecutionResult(
        tool_name=tool_name,
        integration=tool_name,
        status=status,
        command=[
            tool_name,
            "--test",
        ],
        exit_code=0 if status == ToolExecutionStatus.SUCCESS else 1,
        stdout="controlled output",
        stderr="",
        duration_seconds=1.0,
        started_at=timestamp,
        completed_at=timestamp,
        metadata={
            "source_version": "1.0.0",
        },
    )


def build_normalizer():
    """Create a runner with controlled normalization adapters."""
    registry = NormalizationRegistry()

    registry.register(
        FakeAdapter()
    )

    registry.register(
        FailingAdapter()
    )

    pipeline = NormalizationPipeline(
        registry
    )

    from secureforge.core.scan.normalizer import (
        ScanResultNormalizer,
    )

    normalizer = ScanResultNormalizer(
        pipeline
    )

    return normalizer


def test_runner_creates_completed_scan() -> None:
    """Verify a successful runner execution completes the scan."""
    configuration = build_configuration(
        tools=[
            ToolConfiguration(
                name="sast",
                command=["sast", "--scan"],
            )
        ]
    )

    executor = FakeExecutor(
        results={
            "sast": build_result("sast"),
        }
    )

    runner = ScanRunner(
        executor=executor,
        factory=ScanRunFactory(),
        normalizer=build_normalizer(),
    )

    scan = runner.run(
        configuration,
        commit_sha="abc123",
    )

    assert scan.status == ScanStatus.COMPLETED
    assert scan.commit_sha == "abc123"
    assert len(scan.tool_results) == 1


def test_runner_executes_planned_tool() -> None:
    """Verify configured tools are executed."""
    configuration = build_configuration(
        tools=[
            ToolConfiguration(
                name="sast",
                command=["sast", "--scan"],
            )
        ]
    )

    executor = FakeExecutor(
        results={
            "sast": build_result("sast"),
        }
    )

    runner = ScanRunner(
        executor=executor,
        normalizer=build_normalizer(),
    )

    scan = runner.run(
        configuration
    )

    assert scan.tool_results[0].tool_name == "sast"
    assert scan.tool_results[0].succeeded is True


def test_runner_normalizes_successful_tool_results() -> None:
    """Verify successful tool results become findings."""
    configuration = build_configuration(
        tools=[
            ToolConfiguration(
                name="sast",
                command=["sast", "--scan"],
            )
        ]
    )

    executor = FakeExecutor(
        results={
            "sast": build_result("sast"),
        }
    )

    runner = ScanRunner(
        executor=executor,
        normalizer=build_normalizer(),
    )

    scan = runner.run(
        configuration
    )

    assert len(scan.findings) == 1
    assert scan.findings[0].title == "SQL Injection"
    assert scan.findings[0].source == "sast"


def test_runner_uses_application_from_configuration() -> None:
    """Verify normalized findings receive the configured application."""
    configuration = build_configuration(
        tools=[
            ToolConfiguration(
                name="sast",
                command=["sast", "--scan"],
            )
        ]
    )

    executor = FakeExecutor(
        results={
            "sast": build_result("sast"),
        }
    )

    runner = ScanRunner(
        executor=executor,
        normalizer=build_normalizer(),
    )

    scan = runner.run(
        configuration
    )

    assert scan.findings[0].application == "SecureCommerce"


def test_runner_uses_target_reference() -> None:
    """Verify the configured target is passed into normalization."""
    configuration = build_configuration(
        tools=[
            ToolConfiguration(
                name="sast",
                command=["sast", "--scan"],
            )
        ]
    )

    executor = FakeExecutor(
        results={
            "sast": build_result("sast"),
        }
    )

    class RecordingAdapter(NormalizationAdapter):
        source_name = "sast"

        def parse(self, raw_evidence):
            from secureforge.core.normalization import NormalizationResult

            self.target = raw_evidence.target

            return NormalizationResult(
                source="sast",
                findings=[],
                success=True,
            )

    adapter = RecordingAdapter()

    registry = NormalizationRegistry()
    registry.register(adapter)

    pipeline = NormalizationPipeline(
        registry
    )

    from secureforge.core.scan.normalizer import (
        ScanResultNormalizer,
    )

    runner = ScanRunner(
        executor=executor,
        normalizer=ScanResultNormalizer(
            pipeline
        ),
    )

    runner.run(
        configuration
    )

    assert adapter.target == "http://localhost:5000"


def test_runner_records_missing_integration_warning() -> None:
    """Verify missing profile integrations are reported."""
    configuration = build_configuration(
        tools=[]
    )

    runner = ScanRunner(
        executor=FakeExecutor(
            results={}
        )
    )

    scan = runner.run(
        configuration
    )

    assert any(
        "sast" in warning
        for warning in scan.warnings
    )


def test_runner_records_disabled_integration_warning() -> None:
    """Verify disabled integrations are reported separately."""
    configuration = build_configuration(
        tools=[
            ToolConfiguration(
                name="sast",
                enabled=False,
                command=["sast", "--scan"],
            )
        ]
    )

    runner = ScanRunner(
        executor=FakeExecutor(
            results={}
        )
    )

    scan = runner.run(
        configuration
    )

    assert any(
        "disabled" in warning.lower()
        and "sast" in warning
        for warning in scan.warnings
    )


def test_runner_does_not_execute_disabled_tools() -> None:
    """Verify disabled integrations are excluded from execution."""
    configuration = build_configuration(
        tools=[
            ToolConfiguration(
                name="sast",
                enabled=False,
                command=["sast", "--scan"],
            )
        ]
    )

    runner = ScanRunner(
        executor=FakeExecutor(
            results={}
        )
    )

    scan = runner.run(
        configuration
    )

    assert scan.tool_results == []


def test_runner_records_empty_plan_warning() -> None:
    """Verify a scan with no executable tools reports a warning."""
    configuration = build_configuration(
        tools=[]
    )

    runner = ScanRunner(
        executor=FakeExecutor(
            results={}
        )
    )

    scan = runner.run(
        configuration
    )

    assert any(
        "no enabled security tools" in warning.lower()
        for warning in scan.warnings
    )


def test_runner_records_failed_tool() -> None:
    """Verify failed tools are recorded without crashing the scan."""
    configuration = build_configuration(
        tools=[
            ToolConfiguration(
                name="sast",
                command=["sast", "--scan"],
            )
        ]
    )

    result = build_result(
        "sast",
        status=ToolExecutionStatus.FAILED,
    )

    result.error = "Controlled tool failure."

    runner = ScanRunner(
        executor=FakeExecutor(
            results={
                "sast": result,
            }
        )
    )

    scan = runner.run(
        configuration
    )

    assert scan.status == ScanStatus.COMPLETED
    assert scan.tool_error_count == 1
    assert "Controlled tool failure." in scan.errors


def test_runner_records_timeout() -> None:
    """Verify timed-out tools are recorded."""
    configuration = build_configuration(
        tools=[
            ToolConfiguration(
                name="sast",
                command=["sast", "--scan"],
            )
        ]
    )

    result = build_result(
        "sast",
        status=ToolExecutionStatus.TIMEOUT,
    )

    result.error = "Controlled timeout."

    runner = ScanRunner(
        executor=FakeExecutor(
            results={
                "sast": result,
            }
        )
    )

    scan = runner.run(
        configuration
    )

    assert scan.status == ScanStatus.COMPLETED
    assert scan.tool_error_count == 1
    assert "Controlled timeout." in scan.errors


def test_runner_continues_after_failed_tool() -> None:
    """Verify one failed tool does not prevent later tools from running."""
    configuration = build_configuration(
        tools=[
            ToolConfiguration(
                name="sast",
                command=["sast", "--scan"],
            ),
            ToolConfiguration(
                name="sca",
                command=["sca", "--scan"],
            ),
        ]
    )

    first = build_result(
        "sast",
        status=ToolExecutionStatus.FAILED,
    )

    first.error = "SAST failed."

    second = build_result(
        "sca"
    )

    executor = FakeExecutor(
        results={
            "sast": first,
            "sca": second,
        }
    )

    runner = ScanRunner(
        executor=executor
    )

    scan = runner.run(
        configuration
    )

    assert scan.status == ScanStatus.COMPLETED
    assert len(scan.tool_results) == 2
    assert scan.tool_results[0].failed is True
    assert scan.tool_results[1].succeeded is True


def test_runner_normalization_failure_becomes_warning() -> None:
    """Verify failed normalization is recorded as a warning."""
    configuration = build_configuration(
        tools=[
            ToolConfiguration(
                name="sca",
                command=["sca", "--scan"],
            )
        ]
    )

    executor = FakeExecutor(
        results={
            "sca": build_result("sca"),
        }
    )

    runner = ScanRunner(
        executor=executor,
        normalizer=build_normalizer(),
    )

    scan = runner.run(
        configuration
    )

    assert scan.status == ScanStatus.COMPLETED
    assert any(
        "normalization failed" in warning.lower()
        for warning in scan.warnings
    )
    assert scan.findings == []


def test_runner_without_normalizer_still_executes_tools() -> None:
    """Verify normalization is optional during the transition phase."""
    configuration = build_configuration(
        tools=[
            ToolConfiguration(
                name="sast",
                command=["sast", "--scan"],
            )
        ]
    )

    executor = FakeExecutor(
        results={
            "sast": build_result("sast"),
        }
    )

    runner = ScanRunner(
        executor=executor
    )

    scan = runner.run(
        configuration
    )

    assert scan.status == ScanStatus.COMPLETED
    assert len(scan.tool_results) == 1
    assert scan.findings == []


def test_runner_handles_unexpected_exception() -> None:
    """Verify unexpected runner failures produce a failed scan."""
    configuration = build_configuration(
        tools=[
            ToolConfiguration(
                name="sast",
                command=["sast", "--scan"],
            )
        ]
    )

    class ExplodingExecutor:
        def execute(self, tool):
            raise RuntimeError("Unexpected runner failure.")

    runner = ScanRunner(
        executor=ExplodingExecutor()
    )

    scan = runner.run(
        configuration
    )

    assert scan.status == ScanStatus.FAILED
    assert any(
        "unexpectedly" in error.lower()
        for error in scan.errors
    )


def test_runner_preserves_scan_identifier() -> None:
    """Verify scan identifiers are generated normally."""
    configuration = build_configuration()

    runner = ScanRunner(
        executor=FakeExecutor(
            results={}
        )
    )

    scan = runner.run(
        configuration
    )

    assert scan.scan_id.startswith(
        "SCAN-"
    )


def test_runner_updates_finding_summary() -> None:
    """Verify finding statistics are updated after normalization."""
    configuration = build_configuration(
        tools=[
            ToolConfiguration(
                name="sast",
                command=["sast", "--scan"],
            )
        ]
    )

    executor = FakeExecutor(
        results={
            "sast": build_result("sast"),
        }
    )

    runner = ScanRunner(
        executor=executor,
        normalizer=build_normalizer(),
    )

    scan = runner.run(
        configuration
    )

    assert scan.summary.finding_count == 1
    assert scan.summary.high_findings == 1


def test_runner_can_execute_standard_profile() -> None:
    """Verify standard-profile integrations can be planned and executed."""
    configuration = build_configuration(
        profile=ScanProfile.STANDARD,
        tools=[
            ToolConfiguration(
                name="sast",
                command=["sast", "--scan"],
            ),
            ToolConfiguration(
                name="sca",
                command=["sca", "--scan"],
            ),
            ToolConfiguration(
                name="secrets",
                command=["secrets", "--scan"],
            ),
            ToolConfiguration(
                name="api",
                command=["api", "--scan"],
            ),
            ToolConfiguration(
                name="dast",
                command=["dast", "--scan"],
            ),
            ToolConfiguration(
                name="container",
                command=["container", "--scan"],
            ),
        ],
    )

    executor = FakeExecutor(
        results={
            name: build_result(name)
            for name in (
                "sast",
                "sca",
                "secrets",
                "api",
                "dast",
                "container",
            )
        }
    )

    runner = ScanRunner(
        executor=executor
    )

    scan = runner.run(
        configuration
    )

    assert scan.status == ScanStatus.COMPLETED
    assert len(scan.tool_results) == 6
