"""Factory functions for SecureForge runtime configuration."""

from __future__ import annotations

from pathlib import Path

from .runtime import build_runtime


def create_runtime(
    config_path: str | Path | None = None,
    *,
    profile: str | None = None,
):
    """Create a SecureForge runtime from the selected profile."""
    if config_path is not None:
        raise ValueError(
            "config_path is no longer supported; "
            "use the selected runtime profile instead."
        )

    return build_runtime(
        profile=profile or "quick",
    )


__all__ = [
    "create_runtime",
]
