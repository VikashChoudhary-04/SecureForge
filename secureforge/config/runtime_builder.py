"""Compatibility helpers for building SecureForge scan configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secureforge.core.config.models import (
    ScanConfiguration,
    ScanProfile,
    TargetConfiguration,
    TargetType,
)


class RuntimeConfigurationError(ValueError):
    """Raised when runtime scan configuration is invalid."""


def build_scan_configuration(
    *,
    application: str = "securecommerce",
    version: str = "unknown",
    profile: str = "standard",
    target: str | None = None,
    source_path: str | Path | None = None,
    environment: str = "lab",
) -> ScanConfiguration:
    """Build a validated SecureForge scan configuration."""

    try:
        scan_profile = ScanProfile(profile.lower())
    except ValueError as exc:
        allowed = ", ".join(
            item.value
            for item in ScanProfile
        )

        raise RuntimeConfigurationError(
            f"Unsupported scan profile '{profile}'. "
            f"Choose from: {allowed}."
        ) from exc

    base_url = target

    if base_url:
        target_type = TargetType.WEB
    else:
        target_type = TargetType.WEB_AND_API

    target_configuration = TargetConfiguration(
        name=application,
        target_type=target_type,
        base_url=base_url,
        source_path=(
            str(source_path)
            if source_path is not None
            else None
        ),
    )

    return ScanConfiguration(
        application=application,
        version=version,
        profile=scan_profile,
        environment=environment,
        target=target_configuration,
    )


__all__ = [
    "RuntimeConfigurationError",
    "build_scan_configuration",
]
