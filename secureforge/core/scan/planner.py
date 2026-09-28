"""Plan security-tool execution for SecureForge scan profiles."""

from __future__ import annotations

from dataclasses import dataclass, field

from secureforge.core.config import (
    ScanConfiguration,
    ToolConfiguration,
)


@dataclass
class PlannedTool:
    """A tool selected for execution by the scan planner."""

    integration: str
    configuration: ToolConfiguration
    reason: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)


class ScanPlanner:
    """Select enabled security integrations for a scan."""

    def plan(
        self,
        configuration: ScanConfiguration,
    ) -> list[PlannedTool]:
        """Build an execution plan from scan configuration."""
        planned: list[PlannedTool] = []

        for tool in configuration.tools:
            if not tool.enabled:
                continue

            planned.append(
                PlannedTool(
                    integration=tool.name,
                    configuration=tool,
                    reason=(
                        f"Tool '{tool.name}' is enabled "
                        "for the selected scan profile."
                    ),
                )
            )

        return planned

    def missing_integrations(
        self,
        configuration: ScanConfiguration,
    ) -> list[str]:
        """Return integrations required by the profile but not configured."""
        required = set(
            configuration.required_integrations
        )

        configured = {
            tool.name
            for tool in configuration.tools
        }

        return sorted(
            required - configured
        )

    def disabled_integrations(
        self,
        configuration: ScanConfiguration,
    ) -> list[str]:
        """Return configured integrations that are disabled."""
        return sorted(
            tool.name
            for tool in configuration.tools
            if not tool.enabled
        )
