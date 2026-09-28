"""Scan planning logic for SecureForge verification profiles."""

from __future__ import annotations

from dataclasses import dataclass

from secureforge.core.config import (
ScanConfiguration,
get_profile,
)
from secureforge.core.config.models import ToolConfiguration

@dataclass(frozen=True)
class PlannedTool:
"""A tool selected for execution by the scan planner."""

    integration: str
    configuration: ToolConfiguration

class ScanPlanner:
"""Translate scan profiles into executable security integrations."""

    def plan(
        self,
        configuration: ScanConfiguration,
    ) -> list[PlannedTool]:
        """Create an execution plan for a scan configuration."""
        profile = get_profile(
            configuration.profile
        )
    
        configured_tools = {
            tool.name.strip().lower(): tool
            for tool in configuration.tools
            if tool.enabled
        }
    
        planned: list[PlannedTool] = []
    
        for integration in profile.integrations:
            tool = self._find_tool(
                configured_tools,
                integration,
            )
    
            if tool is None:
                continue
    
            planned.append(
                PlannedTool(
                    integration=integration,
                    configuration=tool,
                )
            )
    
        return planned
    
    def required_integrations(
        self,
        configuration: ScanConfiguration,
    ) -> tuple[str, ...]:
        """Return integrations required by the selected profile."""
        profile = get_profile(
            configuration.profile
        )
    
        return profile.integrations
    
    def missing_integrations(
        self,
        configuration: ScanConfiguration,
    ) -> list[str]:
        """Return profile integrations with no configured tool."""
        configured_names = {
            tool.name.strip().lower()
            for tool in configuration.tools
        }
    
        return [
            integration
            for integration in self.required_integrations(
                configuration
            )
            if integration not in configured_names
        ]
    
    def disabled_integrations(
        self,
        configuration: ScanConfiguration,
    ) -> list[str]:
        """Return profile integrations that are explicitly disabled."""
        disabled_names = {
            tool.name.strip().lower()
            for tool in configuration.tools
            if not tool.enabled
        }
    
        return [
            integration
            for integration in self.required_integrations(
                configuration
            )
            if integration in disabled_names
        ]
    
    @staticmethod
    def _find_tool(
        configured_tools: dict[str, ToolConfiguration],
        integration: str,
    ) -> ToolConfiguration | None:
        """Find an enabled tool matching an integration name."""
        return configured_tools.get(
            integration.strip().lower()
        )
