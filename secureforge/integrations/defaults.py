"""Default SecureForge integration definitions."""

from __future__ import annotations


DEFAULT_INTEGRATIONS = (
    "api",
    "container",
    "dast",
    "iac",
    "manual",
    "nessus",
    "nmap",
    "sast",
    "sca",
    "secrets",
)


def default_integration_names() -> tuple[str, ...]:
    """Return the names of all built-in security integrations."""
    return DEFAULT_INTEGRATIONS


__all__ = [
    "DEFAULT_INTEGRATIONS",
    "default_integration_names",
]
