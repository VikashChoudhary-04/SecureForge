"""Default SecureForge integration definitions."""

from __future__ import annotations

DEFAULT_INTEGRATIONS = (
    "api",
    "ci",
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
    """Return the names of all built-in integrations."""
    return DEFAULT_INTEGRATIONS
