"""Static Application Security Testing integrations for SecureForge."""

from .generic import GenericSASTIntegration


SASTIntegration = GenericSASTIntegration


__all__ = [
    "SASTIntegration",
    "GenericSASTIntegration",
]
