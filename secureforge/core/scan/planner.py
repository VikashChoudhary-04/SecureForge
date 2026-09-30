"""Plan security-tool execution for SecureForge scan profiles."""

from __future__ import annotations

from dataclasses import dataclass, field

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
                    configuration=tool,
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
        """Return integrations required by the profile but not configured."""
        required = set(
            self.required_integrations(
                configuration
            )
        )

        configured = {
            tool.name.strip().lower()
            for tool in configuration.tools
        }

        return sorted(
            required - configured
        )

    def disabled_integrations(
        self,
        configuration: ScanConfiguration,
    ) -> list[str]:
        """Return configured profile integrations that are disabled."""
        required = set(
            self.required_integrations(
                configuration
            )
        )

        return sorted(
            tool.name.strip().lower()
            for tool in configuration.tools
            if (
                tool.name.strip().lower() in required
                and not tool.enabled
            )
        )

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
