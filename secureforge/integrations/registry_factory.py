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
    """Build the default registry of security-tool integrations."""
    del configuration
    return IntegrationRegistry(
        integrations=[
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
    )


def build_default_integration_registry() -> IntegrationRegistry:
    return build_default_registry()


def build_registry(
    *,
    configuration: ScanConfiguration | None = None,
    additional_integrations=None,
) -> IntegrationRegistry:
    registry = build_default_registry(configuration=configuration)
    for integration in additional_integrations or []:
        registry.register(integration)
    return registry


__all__ = [
    "build_default_integration_registry",
    "build_default_registry",
    "build_registry",
]

