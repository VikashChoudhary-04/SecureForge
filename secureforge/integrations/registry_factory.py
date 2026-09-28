"""Factory for the default SecureForge integration registry."""

from __future__ import annotations

from .api import APIIntegration
from .ci import CIIntegration
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


def build_default_integration_registry() -> IntegrationRegistry:
    """Build the registry containing all built-in integrations."""
    integrations = [
        APIIntegration(),
        CIIntegration(),
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


__all__ = [
    "build_default_integration_registry",
]
