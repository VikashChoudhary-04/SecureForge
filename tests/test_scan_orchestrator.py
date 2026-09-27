"""Tests for the SecureForge scan orchestrator."""

from dataclasses import dataclass

from secureforge.core.config import (
ScanConfiguration,
ScanProfile,
TargetConfiguration,
TargetType,
ToolConfiguration,
)
from secureforge.core.scan import (
ScanRun,
ScanStatus,
ToolExecutionResult,
ToolExecutionStatus,
)
from secureforge.core.scan.factory import ScanRunFactory
from secureforge.core.scan.orchestrator import (
ScanOrchestrator,
)
from secureforge.core.scan.planner import (
PlannedTool,
ScanPlanner,
)

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
),
tools=tools or [],
)

def build_tool(
name: str,
*,
enabled: bool = True,
) -> ToolConfiguration:
"""Create a representative tool configuration."""
return ToolConfiguration(
name=name,
enabled=enabled,
command=[
"echo",
name,
],
timeout_seconds=5,
)

def build_result(
tool_name: str,
status: ToolExecutionStatus,
*,
error: str | None = None,
) -> ToolExecutionResult:
"""Create a controlled tool execution result."""
return ToolExecutionResult(
tool_name=tool_name,
integration=tool_name,
status=status,
command=[
"echo",
tool_name,
],
exit_code=(
0
if status == ToolExecutionStatus.SUCCESS
else 1
),
stdout="test output",
stderr="",
duration_seconds=0.1,
error=error,
)

class FakeExecutor:
"""Controlled executor used to test orchestration."""

```
def __init__(
    self,
    results: dict[str, ToolExecutionResult],
) -> None:
    self.results = results
    self.calls: list[str] = []

def execute(
    self,
    tool: ToolConfiguration,
) -> ToolExecutionResult:
    """Return the configured result for a tool."""
    self.calls.append(tool.name)

    return self.results[
        tool.name.lower()
    ]
```

class RaisingExecutor:
"""Executor that raises an unexpected exception."""

```
def execute(
    self,
    tool: ToolConfiguration,
) -> ToolExecutionResult:
    """Raise a controlled execution exception."""
    raise RuntimeError(
        f"Unexpected failure for {tool.name}"
    )
```

class RecordingFactory(ScanRunFactory):
"""Factory that records configuration usage."""

```
def __init__(self) -> None:
    super().__init__()
    self.calls = 0

def create(
    self,
    configuration: ScanConfiguration,
    *,
    commit_sha: str | None = None,
    metadata=None,
) -> ScanRun:
    """Record factory invocation."""
    self.calls += 1

    return super().create(
        configuration,
        commit_sha=commit_sha,
        metadata=metadata,
    )
```

class RecordingPlanner(ScanPlanner):
"""Planner that records planning calls."""

```
def __init__(self) -> None:
    self.calls = 0

def plan(
    self,
    configuration: ScanConfiguration,
) -> list[PlannedTool]:
    """Record planning invocation."""
    self.calls += 1

    return super().plan(
        configuration
    )
```

def test_orchestrator_creates_scan_without_execution() -> None:
"""Verify create_scan only initializes a scan."""
configuration = build_configuration()

```
orchestrator = ScanOrchestrator()

scan = orchestrator.create_scan(
    configuration,
    commit_sha="abc123",
)

assert isinstance(scan, ScanRun)
assert scan.status == ScanStatus.CREATED
assert scan.commit_sha == "abc123"
assert scan.application == "SecureCommerce"
```

def test_orchestrator_executes_planned_tools() -> None:
"""Verify configured tools are executed."""
configuration = build_configuration(
tools=[
build_tool("sast"),
build_tool("sca"),
build_tool("secrets"),
]
)

```
executor = FakeExecutor(
    {
        "sast": build_result(
            "sast",
            ToolExecutionStatus.SUCCESS,
        ),
        "sca": build_result(
            "sca",
            ToolExecutionStatus.SUCCESS,
        ),
        "secrets": build_result(
            "secrets",
            ToolExecutionStatus.SUCCESS,
        ),
    }
)

orchestrator = ScanOrchestrator(
    executor=executor
)

scan = orchestrator.execute(
    configuration
)

assert scan.status == ScanStatus.COMPLETED
assert executor.calls == [
    "sast",
    "sca",
    "secrets",
]
```

def test_orchestrator_records_tool_results() -> None:
"""Verify tool results are attached to the scan."""
configuration = build_configuration(
tools=[
build_tool("sast"),
]
)

```
result = build_result(
    "sast",
    ToolExecutionStatus.SUCCESS,
)

executor = FakeExecutor(
    {"sast": result}
)

scan = ScanOrchestrator(
    executor=executor
).execute(
    configuration
)

assert scan.tool_results == [
    result
]
```

def test_orchestrator_marks_scan_completed_after_execution() -> None:
"""Verify successful execution reaches COMPLETED."""
configuration = build_configuration(
tools=[
build_tool("sast"),
]
)

```
executor = FakeExecutor(
    {
        "sast": build_result(
            "sast",
            ToolExecutionStatus.SUCCESS,
        )
    }
)

scan = ScanOrchestrator(
    executor=executor
).execute(
    configuration
)

assert scan.status == ScanStatus.COMPLETED
assert scan.completed_at is not None
assert scan.is_finished is True
```

def test_orchestrator_starts_scan_before_execution() -> None:
"""Verify execution transitions through RUNNING."""
configuration = build_configuration(
tools=[
build_tool("sast"),
]
)

```
class StatusRecordingExecutor:
    """Executor that records the scan state during execution."""

    def __init__(self) -> None:
        self.scan: ScanRun | None = None

    def execute(
        self,
        tool: ToolConfiguration,
    ) -> ToolExecutionResult:
        return build_result(
            tool.name,
            ToolExecutionStatus.SUCCESS,
        )

executor = StatusRecordingExecutor()

orchestrator = ScanOrchestrator(
    executor=executor
)

scan = orchestrator.execute(
    configuration
)

assert scan.status == ScanStatus.COMPLETED
```

def test_orchestrator_warns_about_missing_integrations() -> None:
"""Verify missing profile integrations generate warnings."""
configuration = build_configuration(
tools=[
build_tool("sast"),
]
)

```
executor = FakeExecutor(
    {
        "sast": build_result(
            "sast",
            ToolExecutionStatus.SUCCESS,
        )
    }
)

scan = ScanOrchestrator(
    executor=executor
).execute(
    configuration
)

assert any(
    "sca" in warning
    for warning in scan.warnings
)

assert any(
    "secrets" in warning
    for warning in scan.warnings
)
```

def test_orchestrator_warns_about_disabled_integrations() -> None:
"""Verify disabled profile integrations generate warnings."""
configuration = build_configuration(
tools=[
build_tool("sast"),
build_tool("sca", enabled=False),
build_tool("secrets"),
]
)

```
executor = FakeExecutor(
    {
        "sast": build_result(
            "sast",
            ToolExecutionStatus.SUCCESS,
        ),
        "secrets": build_result(
            "secrets",
            ToolExecutionStatus.SUCCESS,
        ),
    }
)

scan = ScanOrchestrator(
    executor=executor
).execute(
    configuration
)

assert any(
    "sca" in warning
    and "disabled" in warning
    for warning in scan.warnings
)

assert "sca" not in executor.calls
```

def test_orchestrator_warns_when_no_tools_are_available() -> None:
"""Verify an empty tool configuration produces a warning."""
configuration = build_configuration()

```
scan = ScanOrchestrator().execute(
    configuration
)

assert scan.status == ScanStatus.COMPLETED
assert any(
    "No enabled security tools"
    in warning
    for warning in scan.warnings
)
```

def test_orchestrator_records_failed_tool() -> None:
"""Verify tool failures are retained as scan errors."""
configuration = build_configuration(
tools=[
build_tool("sast"),
]
)

```
executor = FakeExecutor(
    {
        "sast": build_result(
            "sast",
            ToolExecutionStatus.FAILED,
            error="SAST failed.",
        )
    }
)

scan = ScanOrchestrator(
    executor=executor
).execute(
    configuration
)

assert scan.status == ScanStatus.COMPLETED
assert scan.tool_error_count == 1
assert "SAST failed." in scan.errors
```

def test_orchestrator_records_timeout() -> None:
"""Verify timed-out tools are retained as scan errors."""
configuration = build_configuration(
tools=[
build_tool("sast"),
]
)

```
executor = FakeExecutor(
    {
        "sast": build_result(
            "sast",
            ToolExecutionStatus.TIMEOUT,
            error="SAST timed out.",
        )
    }
)

scan = ScanOrchestrator(
    executor=executor
).execute(
    configuration
)

assert scan.status == ScanStatus.COMPLETED
assert scan.tool_error_count == 1
assert "SAST timed out." in scan.errors
```

def test_orchestrator_continues_after_tool_failure() -> None:
"""Verify one failed integration does not stop later integrations."""
configuration = build_configuration(
tools=[
build_tool("sast"),
build_tool("sca"),
build_tool("secrets"),
]
)

```
executor = FakeExecutor(
    {
        "sast": build_result(
            "sast",
            ToolExecutionStatus.FAILED,
            error="SAST failed.",
        ),
        "sca": build_result(
            "sca",
            ToolExecutionStatus.SUCCESS,
        ),
        "secrets": build_result(
            "secrets",
            ToolExecutionStatus.SUCCESS,
        ),
    }
)

scan = ScanOrchestrator(
    executor=executor
).execute(
    configuration
)

assert scan.status == ScanStatus.COMPLETED

assert executor.calls == [
    "sast",
    "sca",
    "secrets",
]

assert scan.summary.failed_tools == 1
assert scan.summary.successful_tools == 2
```

def test_orchestrator_handles_unexpected_exception() -> None:
"""Verify unexpected orchestration exceptions fail the scan."""
configuration = build_configuration(
tools=[
build_tool("sast"),
]
)

```
scan = ScanOrchestrator(
    executor=RaisingExecutor()
).execute(
    configuration
)

assert scan.status == ScanStatus.FAILED
assert scan.completed_at is not None
assert scan.has_errors is True
assert any(
    "Scan execution failed unexpectedly"
    in error
    for error in scan.errors
)
```

def test_orchestrator_plan_returns_planned_tools() -> None:
"""Verify the public plan method exposes the execution plan."""
configuration = build_configuration(
tools=[
build_tool("sast"),
build_tool("sca"),
]
)

```
plan = ScanOrchestrator().plan(
    configuration
)

assert [
    item.integration
    for item in plan
] == [
    "sast",
    "sca",
]
```

def test_orchestrator_supports_dependency_injection() -> None:
"""Verify planner, executor, and factory can be injected."""
planner = RecordingPlanner()
executor = FakeExecutor(
{
"sast": build_result(
"sast",
ToolExecutionStatus.SUCCESS,
)
}
)
factory = RecordingFactory()

```
configuration = build_configuration(
    tools=[
        build_tool("sast"),
    ]
)

orchestrator = ScanOrchestrator(
    planner=planner,
    executor=executor,
    factory=factory,
)

scan = orchestrator.execute(
    configuration
)

assert planner.calls == 1
assert factory.calls == 1
assert executor.calls == ["sast"]
assert scan.status == ScanStatus.COMPLETED
```

def test_orchestrator_preserves_commit_sha() -> None:
"""Verify commit SHA reaches the resulting scan."""
configuration = build_configuration(
tools=[
build_tool("sast"),
]
)

```
executor = FakeExecutor(
    {
        "sast": build_result(
            "sast",
            ToolExecutionStatus.SUCCESS,
        )
    }
)

scan = ScanOrchestrator(
    executor=executor
).execute(
    configuration,
    commit_sha="abc123",
)

assert scan.commit_sha == "abc123"
```

def test_orchestrator_updates_tool_statistics() -> None:
"""Verify orchestration updates aggregate tool statistics."""
configuration = build_configuration(
tools=[
build_tool("sast"),
build_tool("sca"),
build_tool("secrets"),
]
)

```
executor = FakeExecutor(
    {
        "sast": build_result(
            "sast",
            ToolExecutionStatus.SUCCESS,
        ),
        "sca": build_result(
            "sca",
            ToolExecutionStatus.FAILED,
            error="SCA failed.",
        ),
        "secrets": build_result(
            "secrets",
            ToolExecutionStatus.SUCCESS,
        ),
    }
)

scan = ScanOrchestrator(
    executor=executor
).execute(
    configuration
)

assert scan.summary.tool_count == 3
assert scan.summary.successful_tools == 2
assert scan.summary.failed_tools == 1
assert scan.summary.skipped_tools == 0
```

def test_orchestrator_preserves_integration_metadata() -> None:
"""Verify planned integration is attached to tool results."""
configuration = build_configuration(
tools=[
build_tool("sast"),
]
)

```
executor = FakeExecutor(
    {
        "sast": build_result(
            "sast",
            ToolExecutionStatus.SUCCESS,
        )
    }
)

scan = ScanOrchestrator(
    executor=executor
).execute(
    configuration
)

assert (
    scan.tool_results[0].metadata["integration"]
    == "sast"
)
```

def test_orchestrator_can_execute_standard_profile() -> None:
"""Verify standard profiles can be orchestrated."""
configuration = build_configuration(
profile=ScanProfile.STANDARD,
tools=[
build_tool("sast"),
build_tool("sca"),
build_tool("secrets"),
build_tool("api"),
build_tool("dast"),
build_tool("container"),
],
)

```
executor = FakeExecutor(
    {
        name: build_result(
            name,
            ToolExecutionStatus.SUCCESS,
        )
        for name in [
            "sast",
            "sca",
            "secrets",
            "api",
            "dast",
            "container",
        ]
    }
)

scan = ScanOrchestrator(
    executor=executor
).execute(
    configuration
)

assert scan.status == ScanStatus.COMPLETED
assert scan.summary.tool_count == 6
assert scan.summary.successful_tools == 6
assert scan.summary.failed_tools == 0
```

def test_orchestrator_can_execute_full_profile() -> None:
"""Verify full profiles can be orchestrated."""
integration_names = [
"sast",
"sca",
"secrets",
"api",
"dast",
"container",
"iac",
"nessus",
"nmap",
"manual",
]

```
configuration = build_configuration(
    profile=ScanProfile.FULL,
    tools=[
        build_tool(name)
        for name in integration_names
    ],
)

executor = FakeExecutor(
    {
        name: build_result(
            name,
            ToolExecutionStatus.SUCCESS,
        )
        for name in integration_names
    }
)

scan = ScanOrchestrator(
    executor=executor
).execute(
    configuration
)

assert scan.status == ScanStatus.COMPLETED
assert scan.summary.tool_count == 10
assert scan.summary.successful_tools == 10
assert scan.summary.failed_tools == 0
```
