"""Factory functions for SecureForge runtime configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .loader import ConfigLoader
from .models import RuntimeConfig


def create_runtime(
    config_path: str | Path | None = None,
    *,
    overrides: dict[str, Any] | None = None,
) -> RuntimeConfig:
    """Create a runtime configuration from file and optional overrides."""
    loader = ConfigLoader()

    if config_path is None:
        config = loader.load_default()
    else:
        config = loader.load(
            Path(config_path)
        )

    if overrides:
        config = _apply_overrides(
            config,
            overrides,
        )

    return config


def _apply_overrides(
    config: RuntimeConfig,
    overrides: dict[str, Any],
) -> RuntimeConfig:
    """Apply runtime configuration overrides."""
    if hasattr(
        config,
        "model_copy",
    ):
        return config.model_copy(
            update=overrides
        )

    for key, value in overrides.items():
        setattr(
            config,
            key,
            value,
        )

    return config
