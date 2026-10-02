"""Factory functions for SecureForge runtime configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .loader import ConfigLoader
from .runtime import build_runtime


def create_runtime(
    config_path: str | Path | None = None,
    *,
    profile: str | None = None,
    target: str | None = None,
    source_path: str | Path | None = None,
    overrides: dict[str, Any] | None = None,
):
    """Create a runtime using either the legacy config loader or profile API."""
    if profile is not None or target is not None or source_path is not None:
        return build_runtime(
            profile=profile or "quick",
            target=target,
            source_path=source_path,
        )

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
    if hasattr(config, "model_copy"):
        return config.model_copy(
            update=overrides
        )

    if isinstance(config, dict):
        updated = dict(config)
        updated.update(overrides)
        return updated

    for key, value in overrides.items():
        setattr(config, key, value)

    return config


__all__ = [
    "create_runtime",
]
