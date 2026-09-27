"""Tests for the default SecureForge integration registry."""

from **future** import annotations

from secureforge.integrations.defaults import build_default_registry

def test_build_default_registry() -> None:
"""The default registry should contain all built-in integrations."""
registry = build_default_registry()

```
assert registry.names() == [
    "api",
    "container",
    "dast",
    "iac",
    "manual",
    "nessus",
    "nmap",
    "sast",
    "sca",
    "secrets",
]
```

def test_default_integrations_are_available() -> None:
"""Every built-in integration should be retrievable."""
registry = build_default_registry()

```
for name in (
    "sast",
    "sca",
    "secrets",
    "api",
    "dast",
    "container",
    "iac",
    "nessus",
    "nmap",
    "manual",
):
    integration = registry.get(name)

    assert integration is not None
    assert integration.integration_name == name
```

def test_default_registry_returns_independent_instances() -> None:
"""Each registry build should create independent integration objects."""
first = build_default_registry()
second = build_default_registry()

```
assert first is not second

assert first.get("sast") is not second.get("sast")
assert first.get("nessus") is not second.get("nessus")
assert first.get("manual") is not second.get("manual")
```

def test_default_registry_contains_expected_count() -> None:
"""The built-in registry should contain exactly ten integrations."""
registry = build_default_registry()

```
assert len(registry.all()) == 10
```

def test_default_registry_is_case_insensitive() -> None:
"""Integration lookup should remain case-insensitive."""
registry = build_default_registry()

```
assert registry.get("NMAP") is registry.get("nmap")
assert registry.get("Nessus") is registry.get("nessus")
assert registry.get("MANUAL") is registry.get("manual")
```
