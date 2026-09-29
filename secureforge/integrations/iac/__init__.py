"""Infrastructure-as-Code security integrations for SecureForge."""

from .generic import GenericIACIntegration


IaCIntegration = GenericIACIntegration


__all__ = [
    "IaCIntegration",
    "GenericIACIntegration",
]
