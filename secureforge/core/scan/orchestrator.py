"""Scan orchestration for SecureForge security verification."""

from **future** import annotations

from secureforge.core.config import ScanConfiguration

from .executor import ToolExecutor
from .factory import ScanRunFactory
from .models import (
ScanRun,
ScanStatus,
ToolExecutionStatus,
)
from .planner import ScanPlanner

class ScanOrchestrator:
"""Coordinate SecureForge scan planning and tool execution."""

```
def __init__(
    self,
    *,
    planner: ScanPlanner | None = None,
    executor: ToolExecutor | None = None,
    factory: ScanRunFactory | None = None,
) -> None:
    self.planner = planner or ScanPlanner()
    self.executor = executor or ToolExecutor()
    self.factory = factory or ScanRunFactory()

def create_scan(
    self,
    configuration: ScanConfiguration,
    *,
    commit_sha: str | None = None,
) -> ScanRun:
    """Create a scan run without executing tools."""
    return self.factory.create(
        configuration,
        commit_sha=commit_sha,
    )

def execute(
    self,
    configuration: ScanConfiguration,
    *,
    commit_sha: str | None = None,
) -> ScanRun:
    """Execute the configured security verification scan."""
    scan = self.create_scan(
        configuration,
        commit_sha=commit_sha,
    )

    scan.start()

    planned_tools = self.planner.plan(
        configuration
    )

    missing_integrations = (
        self.planner.missing_integrations(
            configuration
        )
    )

    disabled_integrations = (
        self.planner.disabled_integrations(
            configuration
        )
    )

    for integration in missing_integrations:
        scan.add_warning(
            f"Integration '{integration}' is required "
            f"by profile '{configuration.profile.value}' "
            "but no enabled tool is configured."
        )

    for integration in disabled_integrations:
        scan.add_warning(
            f"Integration '{integration}' is disabled "
            "and will be skipped."
        )

    if not planned_tools:
        scan.add_warning(
            "No enabled security tools were available "
            "for the selected scan profile."
        )

    try:
        for planned_tool in planned_tools:
            result = self.executor.execute(
                planned_tool.configuration
            )

            result.metadata.setdefault(
                "integration",
                planned_tool.integration,
            )

            scan.add_tool_result(
                result
            )

            if result.status == ToolExecutionStatus.FAILED:
                scan.add_error(
                    result.error
                    or (
                        f"Integration "
                        f"'{planned_tool.integration}' failed."
                    )
                )

            elif result.status == ToolExecutionStatus.TIMEOUT:
                scan.add_error(
                    result.error
                    or (
                        f"Integration "
                        f"'{planned_tool.integration}' timed out."
                    )
                )

        scan.complete()

    except Exception as exc:
        scan.fail(
            f"Scan execution failed unexpectedly: {exc}"
        )

    return scan

def plan(
    self,
    configuration: ScanConfiguration,
):
    """Return the execution plan without running tools."""
    return self.planner.plan(
        configuration
    )
```
