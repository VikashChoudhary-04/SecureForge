# SecureForge integration registry tests

from secureforge.integrations.defaults import (
    DEFAULT_INTEGRATIONS,
    default_integration_names,
)
from secureforge.integrations.registry_factory import (
    build_default_integration_registry,
)


def test_default_integration_names_match_registry() -> None:
    registry = build_default_integration_registry()

    assert tuple(registry.names()) == DEFAULT_INTEGRATIONS


def test_ci_is_not_a_security_tool_integration() -> None:
    assert "ci" not in DEFAULT_INTEGRATIONS

    registry = build_default_integration_registry()

    assert "ci" not in registry.names()


def test_default_registry_contains_expected_security_integrations() -> None:
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


def test_default_integration_names_are_stable() -> None:
    assert default_integration_names() == DEFAULT_INTEGRATIONS

