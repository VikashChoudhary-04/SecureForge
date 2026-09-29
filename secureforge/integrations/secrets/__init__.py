"""Secret detection integrations for SecureForge."""

from .generic import GenericSecretsIntegration


SecretsIntegration = GenericSecretsIntegration


__all__ = [
    "SecretsIntegration",
    "GenericSecretsIntegration",
]
