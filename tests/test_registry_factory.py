"""Tests for the SecureForge integration registry factory."""

from __future__ import annotations

from secureforge.integrations.defaults import build_default_registry
from secureforge.integrations.mock import MockSecurityIntegration
from secureforge.integrations.registry_factory import build_registry


def test_build_registry_contains_default_integrations() -> None:
    """The application registry should contain built-in integrations."""
    registry = build_registry()

    default_registry = build_default_registry()

    assert registry.names() == default_registry.names()


def test_build_registry_supports_additional_integrations() -> None:
    """Custom integrations should be registered."""
    custom = MockSecurityIntegration(
        name="custom-test",
    )

    registry = build_registry(
        additional_integrations=[custom],
    )

    assert registry.contains("custom-test")
    assert registry.get("custom-test") is custom


def test_build_registry_preserves_default_integrations() -> None:
    """Adding a custom integration should not remove built-ins."""
    custom = MockSecurityIntegration(
        name="custom-test",
    )

    registry = build_registry(
        additional_integrations=[custom],
    )

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
    assert registry.contains("custom-test")


def test_build_registry_without_additional_integrations() -> None:
    """Additional integrations should be optional."""
    registry = build_registry(
        additional_integrations=None,
    )

    assert registry.contains("sast")
    assert registry.contains("nessus")
    assert registry.contains("manual")


def test_build_registry_accepts_multiple_custom_integrations() -> None:
    """Multiple custom integrations should be registered."""
    first = MockSecurityIntegration(
        name="custom-one",
    )
    second = MockSecurityIntegration(
        name="custom-two",
    )

    registry = build_registry(
        additional_integrations=[
            first,
            second,
        ],
    )

    assert registry.get("custom-one") is first
    assert registry.get("custom-two") is second
