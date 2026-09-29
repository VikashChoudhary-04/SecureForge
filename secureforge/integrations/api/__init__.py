"""API security integrations for SecureForge."""

from .generic import GenericAPIIntegration


APIIntegration = GenericAPIIntegration


__all__ = [
    "APIIntegration",
    "GenericAPIIntegration",
]
