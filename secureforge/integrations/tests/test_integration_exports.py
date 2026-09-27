"""Tests for SecureForge integration package exports."""

from **future** import annotations

from secureforge.integrations import (
IntegrationConfigurationError,
IntegrationError,
IntegrationParseError,
IntegrationRegistry,
SecurityIntegration,
build_default_registry,
)

def test_integration_exports() -> None:
"""Core integration framework exports should be available."""
assert IntegrationConfigurationError is not None
assert IntegrationError is not None
assert IntegrationParseError is not None
assert IntegrationRegistry is not None
assert SecurityIntegration is not None
assert build_default_registry is not None

def test_default_registry_export_is_usable() -> None:
"""The exported registry builder should construct the registry."""
registry = build_default_registry()

```
assert registry.contains("sast")
assert registry.contains("sca")
assert registry.contains("secrets")
assert registry.contains("api")
assert registry.contains("dast")
assert registry.contains("container")
assert registry.contains("iac")
assert registry.contains("nessus")
assert registry.contains("nmap")
assert registry.contains("manual")
```
