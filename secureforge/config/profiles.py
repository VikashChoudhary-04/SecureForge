"""Built-in SecureForge scan profiles."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanProfile:
    """Definition of a SecureForge scan profile."""

    name: str
    integrations: tuple[str, ...]
    description: str


QUICK_PROFILE = ScanProfile(
    name="quick",
    integrations=(
        "sast",
        "sca",
        "secrets",
    ),
    description=(
        "Fast source, dependency, and secret verification."
    ),
)

STANDARD_PROFILE = ScanProfile(
    name="standard",
    integrations=(
        "sast",
        "sca",
        "secrets",
        "api",
        "dast",
        "container",
    ),
    description=(
        "Standard application security verification."
    ),
)

FULL_PROFILE = ScanProfile(
    name="full",
    integrations=(
        "sast",
        "sca",
        "secrets",
        "api",
        "dast",
        "container",
        "iac",
        "nessus",
        "nmap",
        "manual",
    ),
    description=(
        "Full application, infrastructure, and network "
        "security verification."
    ),
)

CI_PROFILE = ScanProfile(
    name="ci",
    integrations=(
        "ci",
    ),
    description=(
        "Deterministic CI verification without requiring "
        "external scanner executables."
    ),
)


PROFILES = {
    QUICK_PROFILE.name: QUICK_PROFILE,
    STANDARD_PROFILE.name: STANDARD_PROFILE,
    FULL_PROFILE.name: FULL_PROFILE,
    CI_PROFILE.name: CI_PROFILE,
}


def get_profile(name: str) -> ScanProfile:
    """Return a configured scan profile."""
    normalized_name = name.strip().lower()

    try:
        return PROFILES[normalized_name]
    except KeyError as exc:
        available = ", ".join(sorted(PROFILES))
        raise ValueError(
            f"Unknown SecureForge profile '{name}'. "
            f"Available profiles: {available}."
        ) from exc


def list_profiles() -> tuple[ScanProfile, ...]:
    """Return all built-in scan profiles."""
    return tuple(PROFILES.values())


__all__ = [
    "CI_PROFILE",
    "FULL_PROFILE",
    "PROFILES",
    "QUICK_PROFILE",
    "STANDARD_PROFILE",
    "ScanProfile",
    "get_profile",
    "list_profiles",
]
