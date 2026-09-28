"""Factory functions for SecureForge runtime configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .loader import ConfigLoader


def create_runtime(
    config_path: str | Path | None = None,
    *,
    overrides: dict[str, Any] | None = None,
) -> Any:
    """Create the SecureForge runtime configuration."""
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
    config: Any,
    overrides: dict[str, Any],
) -> Any:
    """Apply runtime configuration overrides."""
    if hasattr(
        config,
        "model_copy",
    ):
        return config.model_copy(
            update=overrides
        )

    if isinstance(
        config,
        dict,
    ):
        updated = dict(
            config
        )
        updated.update(
            overrides
        )
        return updated

    for key, value in overrides.items():
        setattr(
            config,
            key,
            value,
        )

    return config
