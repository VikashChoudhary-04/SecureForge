"""Factories for constructing SecureForge integration registries."""

from **future** import annotations

from collections.abc import Iterable

from secureforge.integrations.base import SecurityIntegration
from secureforge.integrations.defaults import build_default_registry
from secureforge.integrations.registry import IntegrationRegistry

def build_registry(
additional_integrations: Iterable[SecurityIntegration] | None = None,
) -> IntegrationRegistry:
"""Build the application integration registry."""
registry = build_default_registry()

```
if additional_integrations:
    registry.register_many(additional_integrations)

return registry
```
