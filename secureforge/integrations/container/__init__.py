"""Container security integrations for SecureForge."""

from .generic import GenericContainerIntegration


ContainerIntegration = GenericContainerIntegration


__all__ = [
    "ContainerIntegration",
    "GenericContainerIntegration",
]
