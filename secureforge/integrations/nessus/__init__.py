"""Nessus vulnerability-assessment integrations for SecureForge."""

from .generic import GenericNessusIntegration


NessusIntegration = GenericNessusIntegration


__all__ = [
    "NessusIntegration",
    "GenericNessusIntegration",
]
