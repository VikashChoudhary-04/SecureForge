"""Runtime configuration helpers for SecureForge."""

from **future** import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

class RuntimeConfigurationError(ValueError):
"""Raised when a SecureForge runtime configuration is invalid."""

@dataclass(frozen=True)
class RuntimeConfiguration:
"""Loaded runtime configuration for a SecureForge scan."""

```
path: Path
data: dict[str, Any]

@property
def project(self) -> dict[str, Any]:
    """Return project configuration."""
    return self._section("project")

@property
def scan(self) -> dict[str, Any]:
    """Return scan configuration."""
    return self._section("scan")

@property
def target(self) -> dict[str, Any]:
    """Return target configuration."""
    return self._section("target")

@property
def integrations(self) -> dict[str, Any]:
    """Return integration configuration."""
    return self._section("integrations")

@property
def output(self) -> dict[str, Any]:
    """Return output configuration."""
    return self._section("output")

@property
def policy(self) -> dict[str, Any]:
    """Return policy configuration."""
    return self._section("policy")

@property
def requirements(self) -> dict[str, Any]:
    """Return requirement configuration."""
    return self._section("requirements")

@property
def logging(self) -> dict[str, Any]:
    """Return logging configuration."""
    return self._section("logging")

@property
def profile(self) -> str:
    """Return the configured scan profile."""
    value = self.scan.get("profile", "quick")

    if not isinstance(value, str) or not value.strip():
        raise RuntimeConfigurationError(
            "scan.profile must be a non-empty string."
        )

    return value.strip().lower()

def integration(
    self,
    name: str,
) -> dict[str, Any]:
    """Return configuration for one integration."""
    value = self.integrations.get(name)

    if value is None:
        return {}

    if not isinstance(value, dict):
        raise RuntimeConfigurationError(
            f"Integration '{name}' configuration must be a mapping."
        )

    return dict(value)

def enabled_integrations(self) -> list[str]:
    """Return explicitly enabled integrations."""
    enabled: list[str] = []

    for name, value in self.integrations.items():
        if not isinstance(value, dict):
            raise RuntimeConfigurationError(
                f"Integration '{name}' configuration must be a mapping."
            )

        if value.get("enabled", False):
            enabled.append(name)

    return enabled

def _section(
    self,
    name: str,
) -> dict[str, Any]:
    """Return a named top-level configuration section."""
    value = self.data.get(name, {})

    if value is None:
        return {}

    if not isinstance(value, dict):
        raise RuntimeConfigurationError(
            f"Configuration section '{name}' must be a mapping."
        )

    return value
```

def load_runtime_configuration(
path: str | Path,
) -> RuntimeConfiguration:
"""Load and validate a YAML runtime configuration."""
config_path = Path(path)

```
if not config_path.is_file():
    raise RuntimeConfigurationError(
        f"Configuration file does not exist: {config_path}"
    )

try:
    with config_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        data = yaml.safe_load(file)
except OSError as exc:
    raise RuntimeConfigurationError(
        f"Unable to read configuration file: {config_path}"
    ) from exc
except yaml.YAMLError as exc:
    raise RuntimeConfigurationError(
        f"Invalid YAML configuration: {config_path}"
    ) from exc

if data is None:
    data = {}

if not isinstance(data, dict):
    raise RuntimeConfigurationError(
        "The root configuration value must be a mapping."
    )

configuration = RuntimeConfiguration(
    path=config_path,
    data=data,
)

_validate_runtime_configuration(configuration)

return configuration
```

def _validate_runtime_configuration(
configuration: RuntimeConfiguration,
) -> None:
"""Validate required runtime configuration values."""
if not configuration.project.get("name"):
raise RuntimeConfigurationError(
"project.name is required."
)

```
if not configuration.project.get("application"):
    raise RuntimeConfigurationError(
        "project.application is required."
    )

if not configuration.scan.get("profile"):
    raise RuntimeConfigurationError(
        "scan.profile is required."
    )

if not configuration.integrations:
    raise RuntimeConfigurationError(
        "At least one integration must be configured."
    )
```
