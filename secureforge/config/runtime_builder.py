"""Build typed SecureForge configuration from runtime configuration."""

from __future__ import annotations

import shlex
from typing import Any

from secureforge.config.runtime import (
    RuntimeConfiguration,
    RuntimeConfigurationError,
)
from secureforge.core.config import (
    IntegrationConfiguration,
    ScanConfiguration,
    ScanProfile,
    TargetConfiguration,
    TargetType,
    ToolConfiguration,
)
from secureforge.core.risk import RiskContext


def build_scan_configuration(
    runtime: RuntimeConfiguration,
) -> ScanConfiguration:
    """Build a typed ScanConfiguration from loaded runtime configuration."""

    project = runtime.project
    scan = runtime.scan
    target = runtime.target

    profile_value = runtime.profile

    try:
        profile = ScanProfile(profile_value.lower())
    except ValueError as exc:
        raise RuntimeConfigurationError(
            f"Unsupported scan profile '{profile_value}'"
        ) from exc

    target_type_value = target.get(
        "type",
        target.get("target_type", "web"),
    )

    try:
        target_type = TargetType(target_type_value)
    except ValueError as exc:
        raise RuntimeConfigurationError(
            f"Unsupported target type '{target_type_value}'"
        ) from exc

    integrations = _build_integrations(
        runtime.integrations
    )

    tools = _build_tools(
        runtime.integrations
    )

    target_configuration = TargetConfiguration(
        name=str(
            target.get(
                "name",
                project.get(
                    "application",
                    project.get("name", "target"),
                ),
            )
        ),
        target_type=target_type,
        base_url=target.get("base_url"),
        api_base_url=target.get("api_base_url"),
        openapi_url=target.get("openapi_url"),
        source_path=target.get("source_path"),
        container_image=target.get("container_image"),
        container_path=target.get("container_path"),
        iac_path=target.get("iac_path"),
        network_target=target.get("network_target"),
        evidence_path=target.get("evidence_path"),
        docker_image=target.get("docker_image"),
        metadata=dict(
            target.get(
                "metadata",
                {},
            )
        ),
    )

    risk_data = dict(runtime.risk)

    risk_data.setdefault(
        "environment",
        project.get(
            "environment",
            "unknown",
        ),
    )

    try:
        risk_context = RiskContext.model_validate(
            risk_data
        )
    except ValueError as exc:
        raise RuntimeConfigurationError(
            f"Invalid risk configuration: {exc}"
        ) from exc

    output = runtime.output

    output_directory = output.get(
        "directory",
        output.get(
            "output_directory",
            "reports",
        ),
    )

    return ScanConfiguration(
        application=str(
            project.get(
                "application",
                project.get(
                    "name",
                    "application",
                ),
            )
        ),
        version=str(
            project.get(
                "version",
                scan.get(
                    "version",
                    "1.0.0",
                ),
            )
        ),
        profile=profile,
        environment=str(
            project.get(
                "environment",
                scan.get(
                    "environment",
                    "lab",
                ),
            )
        ),
        risk_context=risk_context,
        target=target_configuration,
        integrations=integrations,
        tools=tools,
        output_directory=str(
            output_directory
        ),
        fail_on_tool_error=bool(
            scan.get(
                "fail_on_tool_error",
                False,
            )
        ),
        metadata=dict(
            project.get(
                "metadata",
                {},
            )
        ),
    )


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


def _build_tools(
    integrations: dict[str, Any],
) -> list[ToolConfiguration]:
    """Build newer typed tool configurations from integrations."""

    tools: list[ToolConfiguration] = []

    for name, configuration in integrations.items():
        if not isinstance(configuration, dict):
            raise RuntimeConfigurationError(
                f"Integration '{name}' configuration must be a mapping"
            )

        metadata = dict(
            configuration.get(
                "metadata",
                {},
            )
        )

        tools.append(
            ToolConfiguration(
                name=name,
                enabled=bool(
                    configuration.get(
                        "enabled",
                        False,
                    )
                ),
                executable=configuration.get(
                    "executable"
                ),
                command=_normalize_command(
                    configuration.get(
                        "command",
                        [],
                    )
                ),
                timeout_seconds=int(
                    configuration.get(
                        "timeout_seconds",
                        300,
                    )
                ),
                arguments=_normalize_string_list(
                    configuration.get(
                        "arguments",
                        [],
                    )
                ),
                environment={
                    str(key): str(value)
                    for key, value in dict(
                        configuration.get(
                            "environment",
                            {},
                        )
                    ).items()
                },
                metadata=metadata,
            )
        )

    return tools


def _normalize_command(
    command: Any,
) -> list[str]:
    """Normalize a configured command into a list."""

    if command is None:
        return []

    if isinstance(command, str):
        return shlex.split(command)

    return _normalize_string_list(command)


def _normalize_string_list(
    values: Any,
) -> list[str]:
    """Normalize a configured value into a list of strings."""

    if values is None:
        return []

    if isinstance(values, str):
        return [values]

    if not isinstance(values, list):
        raise RuntimeConfigurationError(
            "Configured command or argument values must be a string or list"
        )

    return [
        str(value)
        for value in values
    ]


__all__ = [
    "build_scan_configuration",
]
