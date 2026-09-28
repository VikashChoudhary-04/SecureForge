"""Build typed SecureForge scan configuration from runtime YAML."""

from __future__ import annotations

from typing import Any

from .models import (
IntegrationConfig,
ScanConfiguration,
ScanProfile,
TargetConfig,
)
from .runtime import RuntimeConfiguration, RuntimeConfigurationError

def build_scan_configuration(
runtime: RuntimeConfiguration,
) -> ScanConfiguration:
"""Convert runtime YAML configuration into ScanConfiguration."""
profile = _parse_profile(runtime.profile)
target = _build_target(runtime.target)
integrations = _build_integrations(runtime.integrations)

return ScanConfiguration(
    profile=profile,
    target=target,
    integrations=integrations,
)


def _parse_profile(
value: str,
) -> ScanProfile:
"""Convert a profile name into the ScanProfile enum."""
try:
return ScanProfile(value.lower())
except ValueError as exc:
allowed = ", ".join(
profile.value
for profile in ScanProfile
)


    raise RuntimeConfigurationError(
        f"Unsupported scan profile '{value}'. "
        f"Choose from: {allowed}."
    ) from exc

def _build_target(
data: dict[str, Any],
) -> TargetConfig:
"""Build the typed target configuration."""
try:
return TargetConfig(
base_url=data.get("base_url"),
api_base_url=data.get("api_base_url"),
openapi_url=data.get("openapi_url"),
source_path=data.get("source_path"),
container_image=data.get("container_image"),
container_path=data.get("container_path"),
iac_path=data.get("iac_path"),
network_target=data.get("network_target"),
evidence_path=data.get("evidence_path"),
)
except (TypeError, ValueError) as exc:
raise RuntimeConfigurationError(
"Invalid target configuration."
) from exc

def _build_integrations(
data: dict[str, Any],
) -> dict[str, IntegrationConfig]:
"""Build typed integration configuration objects."""
integrations: dict[str, IntegrationConfig] = {}

for name, raw_config in data.items():
    if not isinstance(raw_config, dict):
        raise RuntimeConfigurationError(
            f"Integration '{name}' configuration "
            "must be a mapping."
        )

    options = {
        key: value
        for key, value in raw_config.items()
        if key not in {
            "enabled",
            "command",
        }
    }

    try:
        integrations[name] = IntegrationConfig(
            name=name,
            enabled=bool(
                raw_config.get(
                    "enabled",
                    False,
                )
            ),
            command=raw_config.get("command"),
            options=options,
        )
    except (TypeError, ValueError) as exc:
        raise RuntimeConfigurationError(
            f"Invalid configuration for integration '{name}'."
        ) from exc

return integrations
