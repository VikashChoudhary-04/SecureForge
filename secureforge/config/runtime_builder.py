"""Compatibility helpers for building SecureForge scan configuration."""

from __future__ import annotations

from typing import Any

from secureforge.config.runtime import (
    RuntimeConfiguration,
    RuntimeConfigurationError,
)
from secureforge.core.config.models import (
    ScanConfiguration,
    ScanProfile,
    TargetConfiguration,
    TargetType,
)


class IntegrationConfiguration:
    """Typed configuration for one security integration."""

    def __init__(
        self,
        *,
        name: str,
        enabled: bool = True,
        command: Any = None,
        options: dict[str, Any] | None = None,
    ) -> None:
        self.name = name
        self.enabled = enabled
        self.command = command
        self.options = options or {}


def build_scan_configuration(
    runtime: RuntimeConfiguration,
) -> ScanConfiguration:
    """Build a typed scan configuration from runtime YAML."""

    profile = runtime.profile

    try:
        scan_profile = ScanProfile(profile)
    except ValueError as exc:
        raise RuntimeConfigurationError(
            f"Unsupported scan profile '{profile}'"
        ) from exc

    target = runtime.target

    target_configuration = TargetConfiguration(
        name=runtime.project["application"],
        target_type=_resolve_target_type(target),
        base_url=target.get("base_url"),
        api_base_url=target.get("api_base_url"),
        openapi_url=target.get("openapi_url"),
        source_path=target.get("source_path"),
        container_image=target.get("container_image"),
        container_path=target.get("container_path"),
        iac_path=target.get("iac_path"),
        network_target=target.get("network_target"),
        evidence_path=target.get("evidence_path"),
    )

    integrations = _build_integrations(
        runtime.integrations
    )

    output = runtime.output

    configuration = ScanConfiguration(
        application=runtime.project["application"],
        version=runtime.project.get(
            "version",
            "unknown",
        ),
        profile=scan_profile,
        environment=runtime.project.get(
            "environment",
            "lab",
        ),
        target=target_configuration,
        output_directory=output.get(
            "directory",
            "reports",
        ),
        integrations=integrations,
    )

    return configuration


def _resolve_target_type(
    target: dict[str, Any],
) -> TargetType:
    """Determine the target type from runtime configuration."""
    if target.get("target_type"):
        try:
            return TargetType(
                str(target["target_type"]).strip().lower()
            )
        except ValueError:
            pass

    has_web = bool(
        target.get("base_url")
    )

    has_api = bool(
        target.get("api_base_url")
        or target.get("openapi_url")
    )

    if has_web and has_api:
        return TargetType.WEB_AND_API

    if has_api:
        return TargetType.API

    return TargetType.WEB_AND_API


def _build_integrations(
    integrations: dict[str, Any],
) -> dict[str, IntegrationConfiguration]:
    """Build typed integration configurations."""
    result: dict[str, IntegrationConfiguration] = {}

    for name, configuration in integrations.items():
        if not isinstance(configuration, dict):
            raise RuntimeConfigurationError(
                f"Integration '{name}' configuration must be a mapping"
            )

        options = dict(configuration)

        enabled = bool(
            options.pop(
                "enabled",
                True,
            )
        )

        command = options.pop(
            "command",
            None,
        )

        result[name] = IntegrationConfiguration(
            name=name,
            enabled=enabled,
            command=command,
            options=options,
        )

    return result


__all__ = [
    "IntegrationConfiguration",
    "build_scan_configuration",
]
