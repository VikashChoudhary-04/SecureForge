```python id="7n5q3w"
"""Factory functions for constructing SecureForge runtime services."""

from __future__ import annotations

from pathlib import Path

from .runtime import SecureForgeRuntime, build_runtime


def create_runtime(
    *,
    profile: str = "standard",
    target: str | None = None,
    source_path: Path | None = None,
    config_path: Path | None = None,
) -> SecureForgeRuntime:
    """Create a fully configured SecureForge runtime."""
    return build_runtime(
        profile=profile,
        target=target,
        source_path=source_path,
        config_path=config_path,
    )


__all__ = [
    "SecureForgeRuntime",
    "build_runtime",
    "create_runtime",
]
```
