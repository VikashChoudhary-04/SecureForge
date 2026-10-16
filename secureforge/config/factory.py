"""Factory functions for SecureForge runtime configuration."""

from __future__ import annotations

from .runtime import build_runtime


def create_runtime(
    *,
    profile: str | None = None,
):
    """Create a SecureForge runtime from the selected profile."""
    return build_runtime(
        profile=profile or "quick",
    )


__all__ = [
    "create_runtime",
]
