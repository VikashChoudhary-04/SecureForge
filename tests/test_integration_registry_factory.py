"""Tests for the default SecureForge integration registry."""

from __future__ import annotations

from secureforge.integrations.registry_factory import (
    build_default_integration_registry,
)


def test_default_registry_contains_ci_integration() -> None:
    """The default registry includes the CI integration."""
    registry = build_default_integration_registry()

    integration = registry.get("ci")

    assert integration.name == "ci"


def test_default_registry_contains_expected_integrations() -> None:
    """The default registry contains the built-in integrations."""
    registry = build_default_integration_registry()

    expected = {
        "api",
        "ci",
        "container",
        "dast",
        "iac",
        "manual",
        "nessus",
        "nmap",
        "sast",
        "sca",
        "secrets",
    }

    assert set(registry.names()) == expected


def test_default_registry_can_find_ci_integration() -> None:
    """The registry can resolve the CI integration by name."""
    registry = build_default_integration_registry()

    integration = registry.get("ci")

    assert integration.describe()["name"] == "ci"
    assert integration.describe()["mode"] == "synthetic"
