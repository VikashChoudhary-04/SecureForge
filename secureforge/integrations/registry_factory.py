"""Factory functions for SecureForge security-tool integrations."""

from __future__ import annotations

from secureforge.core.config import ScanConfiguration

from .api import APIIntegration
from .container import ContainerIntegration
from .dast import DASTIntegration
from .iac import IaCIntegration
from .manual import ManualIntegration
from .nessus import NessusIntegration
from .nmap import NmapIntegration
from .registry import IntegrationRegistry
from .sast import SASTIntegration
from .sca import SCAIntegration
from .secrets import SecretsIntegration


def build_default_registry(
    *,
    configuration: ScanConfiguration | None = None,
) -> IntegrationRegistry:
    """Build the default SecureForge integration registry.

    The optional configuration argument is accepted for compatibility
    with the runtime construction layer. Individual integrations receive
    the scan configuration later during command construction.
    """
    del configuration

    integrations = [
        APIIntegration(),
        ContainerIntegration(),
        DASTIntegration(),
        IaCIntegration(),
        ManualIntegration(),
        NessusIntegration(),
        NmapIntegration(),
        SASTIntegration(),
        SCAIntegration(),
        SecretsIntegration(),
    ]

    return IntegrationRegistry(
        integrations=integrations,
    )


def build_default_integration_registry() -> IntegrationRegistry:
    """Build the default registry without a scan configuration."""
    return build_default_registry()


def build_registry(
    *,
    configuration: ScanConfiguration | None = None,
) -> IntegrationRegistry:
    """Build a SecureForge integration registry."""
    return build_default_registry(
        configuration=configuration,
    )


__all__ = [
    "build_default_integration_registry",
    "build_default_registry",
    "build_registry",
]
