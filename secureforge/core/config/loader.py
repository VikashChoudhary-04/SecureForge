"""Configuration loading utilities for SecureForge."""

from **future** import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import ScanConfiguration

class ConfigurationLoader:
"""Load and validate SecureForge YAML configuration."""

```
def load_file(
    self,
    path: str | Path,
) -> ScanConfiguration:
    """Load a SecureForge configuration from a YAML file."""
    configuration_path = Path(path)

    if not configuration_path.exists():
        raise FileNotFoundError(
            f"Configuration file '{configuration_path}' was not found."
        )

    if not configuration_path.is_file():
        raise ValueError(
            f"Configuration path '{configuration_path}' is not a file."
        )

    try:
        with configuration_path.open(
            "r",
            encoding="utf-8",
        ) as file:
            data = yaml.safe_load(file)
    except yaml.YAMLError as exc:
        raise ValueError(
            f"Invalid YAML configuration in "
            f"'{configuration_path}': {exc}"
        ) from exc

    return self.load_data(data)

def load_data(
    self,
    data: Any,
) -> ScanConfiguration:
    """Validate raw configuration data."""
    if data is None:
        raise ValueError(
            "Configuration file is empty."
        )

    if not isinstance(data, dict):
        raise ValueError(
            "SecureForge configuration must contain a YAML mapping."
        )

    try:
        return ScanConfiguration.model_validate(data)
    except Exception as exc:
        raise ValueError(
            f"Invalid SecureForge configuration: {exc}"
        ) from exc

@staticmethod
def dump_data(
    configuration: ScanConfiguration,
) -> dict[str, Any]:
    """Convert a configuration model into serializable data."""
    return configuration.model_dump(
        mode="json",
    )

def save_file(
    self,
    configuration: ScanConfiguration,
    path: str | Path,
) -> None:
    """Save a validated configuration as YAML."""
    configuration_path = Path(path)

    configuration_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    data = self.dump_data(configuration)

    with configuration_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        yaml.safe_dump(
            data,
            file,
            sort_keys=False,
            default_flow_style=False,
        )
```
