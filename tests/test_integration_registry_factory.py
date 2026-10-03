"""Tests for the default SecureForge integration registry."""

from __future__ import annotations

from secureforge.integrations.registry_factory import (
    build_default_integration_registry,
)


def test_default_registry_contains_expected_integrations() -> None:
    """The default registry contains the built-in security integrations."""
    registry = build_default_integration_registry()

    expected = {
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
    }

    assert set(registry.names()) == expected
