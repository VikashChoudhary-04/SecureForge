"""Nmap network reconnaissance integrations for SecureForge."""

from .generic import GenericNmapIntegration


NmapIntegration = GenericNmapIntegration


__all__ = [
    "NmapIntegration",
    "GenericNmapIntegration",
]
