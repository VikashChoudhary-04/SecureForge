"""Configuration loading for SecureForge."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

class ConfigLoadError(Exception):
"""Raised when SecureForge configuration cannot be loaded."""

class ConfigLoader:
"""Load SecureForge YAML configuration files."""


def __init__(
    self,
    config_directory: Path | None = None,
) -> None:
    self.config_directory = (
        config_directory
        if config_directory is not None
        else Path(__file__).resolve().parent
    )

def load_profile(
    self,
    profile: str,
) -> dict[str, Any]:
    """Load a built-in profile configuration."""
    normalized_profile = profile.strip().lower()

    if normalized_profile not in {
        "quick",
        "standard",
        "full",
        "ci",
    }:
        raise ConfigLoadError(
            "Unknown SecureForge profile "
            f"'{profile}'. Available profiles: "
            "quick, standard, full, ci."
        )

    config_path = (
        self.config_directory
        / f"{normalized_profile}.yaml"
    )

    return self.load_file(config_path)

def load_file(
    self,
    path: Path,
) -> dict[str, Any]:
    """Load and validate a YAML configuration file."""
    if not path.exists():
        raise ConfigLoadError(
            f"Configuration file does not exist: {path}"
        )

    if not path.is_file():
        raise ConfigLoadError(
            f"Configuration path is not a file: {path}"
        )

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as handle:
            data = yaml.safe_load(handle)
    except OSError as exc:
        raise ConfigLoadError(
            f"Unable to read configuration file: {path}"
        ) from exc
    except yaml.YAMLError as exc:
        raise ConfigLoadError(
            f"Invalid YAML configuration: {path}"
        ) from exc

    if data is None:
        return {}

    if not isinstance(data, dict):
        raise ConfigLoadError(
            "SecureForge configuration root must "
            "be a mapping."
        )

    return data

def list_profiles(self) -> tuple[str, ...]:
    """Return available built-in profile names."""
    profiles = []

    for path in sorted(
        self.config_directory.glob("*.yaml")
    ):
        if path.name in {
            "default.yaml",
        }:
            profiles.append(path.stem)

    return tuple(profiles)


__all__ = [
"ConfigLoadError",
"ConfigLoader",
]
