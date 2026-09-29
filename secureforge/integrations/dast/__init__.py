"""Dynamic Application Security Testing integrations for SecureForge."""

from .generic import GenericDASTIntegration


DASTIntegration = GenericDASTIntegration


__all__ = [
    "DASTIntegration",
    "GenericDASTIntegration",
]
