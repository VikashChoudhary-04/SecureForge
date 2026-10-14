"""Plan security-tool execution for SecureForge scan profiles."""

from __future__ import annotations

from dataclasses import dataclass, field
import re

from secureforge.core.config import (
    ScanConfiguration,
    ScanProfile,
    ToolConfiguration,
)


@dataclass
class PlannedTool:
    """A tool selected for execution by the scan planner."""

    integration: str
    configuration: ToolConfiguration
    reason: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass
class ScanPlan:
    """A collection of planned security-tool executions."""

    tools: list[PlannedTool] = field(
        default_factory=list
    )


class ScanPlanner:
    """Select enabled security integrations for a scan."""

    PROFILE_INTEGRATIONS: dict[ScanProfile, tuple[str, ...]] = {
        ScanProfile.QUICK: (
            "sast",
            "sca",
            "secrets",
        ),
        ScanProfile.STANDARD: (
            "sast",
            "sca",
            "secrets",
            "api",
            "dast",
            "container",
        ),
        ScanProfile.FULL: (
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
        ),
        ScanProfile.CI: (
            "sast",
            "sca",
            "secrets",
        ),
    }

    TARGET_PLACEHOLDERS: dict[str, str] = {
        "base_url": "base_url",
        "container_image": "container_image",
        "iac_path": "iac_path",
        "network_target": "network_target",
        "openapi_url": "openapi_url",
        "source_path": "source_path",
    }

    PLACEHOLDER_PATTERN = re.compile(
        r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}"
    )

    def required_integrations(
        self,
        configuration: ScanConfiguration,
    ) -> tuple[str, ...]:
        """Return integrations required by the selected scan profile."""
        profile = self._normalize_profile(
            configuration.profile
        )

        return self.PROFILE_INTEGRATIONS.get(
            profile,
            (),
        )

    def plan(
        self,
        configuration: ScanConfiguration,
    ) -> list[PlannedTool]:
        """Build an execution plan from enabled profile tools."""
        required = self.required_integrations(
            configuration
        )
        configured = {
            tool.name.strip().lower(): tool
            for tool in configuration.tools
        }

        planned: list[PlannedTool] = []

        for integration in required:
            tool = configured.get(integration)

            if tool is None or not tool.enabled:
                continue

            planned.append(
                PlannedTool(
                    integration=integration,
                    configuration=self._render_tool_configuration(
                        tool,
                        configuration,
                    ),
                    reason=(
                        f"Tool '{integration}' is enabled "
                        "for the selected scan profile."
                    ),
                )
            )

        return planned

    def missing_integrations(
        self,
        configuration: ScanConfiguration,
    ) -> list[str]:
        """Return required but unconfigured integrations in profile order."""
        required = self.required_integrations(
            configuration
        )

        configured = {
            tool.name.strip().lower()
            for tool in configuration.tools
        }

        return [
            integration
            for integration in required
            if integration not in configured
        ]

    def disabled_integrations(
        self,
        configuration: ScanConfiguration,
    ) -> list[str]:
        """Return configured profile integrations that are disabled."""
        required = self.required_integrations(
            configuration
        )

        configured = {
            tool.name.strip().lower(): tool
            for tool in configuration.tools
        }

        return [
            integration
            for integration in required
            if (
                integration in configured
                and not configured[integration].enabled
            )
        ]

    def _render_tool_configuration(
        self,
        tool: ToolConfiguration,
        configuration: ScanConfiguration,
    ) -> ToolConfiguration:
        """Resolve target placeholders in a tool configuration."""
        values = self._target_values(
            configuration
        )

        return tool.model_copy(
            update={
                "command": [
                    self._render_value(
                        value,
                        values,
                    )
                    for value in tool.command
                ],
                "arguments": [
                    self._render_value(
                        value,
                        values,
                    )
                    for value in tool.arguments
                ],
            }
        )

    @classmethod
    def _render_value(
        cls,
        value: str,
        values: dict[str, str | None],
    ) -> str:
        """Render supported placeholders in one command value."""

        def replace(match: re.Match[str]) -> str:
            placeholder = match.group(1)

            if placeholder not in cls.TARGET_PLACEHOLDERS:
                raise ValueError(
                    f"Unsupported command placeholder "
                    f"'{{{placeholder}}}'."
                )

            target_field = cls.TARGET_PLACEHOLDERS[
                placeholder
            ]
            resolved = values.get(
                target_field
            )

            if resolved is None or not str(resolved).strip():
                raise ValueError(
                    f"Target value '{target_field}' is required "
                    f"to resolve '{{{placeholder}}}'."
                )

            return str(resolved)

        return cls.PLACEHOLDER_PATTERN.sub(
            replace,
            value,
        )

    @staticmethod
    def _target_values(
        configuration: ScanConfiguration,
    ) -> dict[str, str | None]:
        """Return target values available for command rendering."""
        target = configuration.target

        return {
            "base_url": target.base_url,
            "container_image": target.container_image,
            "iac_path": target.iac_path,
            "network_target": target.network_target,
            "openapi_url": target.openapi_url,
            "source_path": target.source_path,
        }

    @staticmethod
    def _normalize_profile(
        profile: ScanProfile | str,
    ) -> ScanProfile:
        """Normalize a scan profile to the supported enum."""
        if isinstance(
            profile,
            ScanProfile,
        ):
            return profile

        return ScanProfile(
            str(profile).strip().lower()
        )


__all__ = [
    "PlannedTool",
    "ScanPlan",
    "ScanPlanner",
]
