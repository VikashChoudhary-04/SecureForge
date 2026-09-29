"""Software Composition Analysis integrations for SecureForge."""

from .generic import GenericSCAIntegration


SCAIntegration = GenericSCAIntegration


__all__ = [
    "SCAIntegration",
    "GenericSCAIntegration",
]
