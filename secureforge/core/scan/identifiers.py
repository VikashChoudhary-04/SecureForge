"""Deterministic scan identifier generation for SecureForge."""

from **future** import annotations

import hashlib
import re

from secureforge.core.config import ScanProfile

class ScanIdentifier:
"""Generate stable identifiers for SecureForge scan runs."""

```
PREFIX = "SCAN"

@classmethod
def generate(
    cls,
    *,
    application: str,
    version: str,
    profile: ScanProfile | str,
    commit_sha: str | None = None,
    environment: str | None = None,
) -> str:
    """Generate a deterministic scan identifier."""
    canonical_parts = [
        cls._normalize(application),
        cls._normalize(version),
        cls._normalize_profile(profile),
        cls._normalize(commit_sha),
        cls._normalize(environment),
    ]

    canonical_value = "|".join(
        canonical_parts
    )

    digest = hashlib.sha256(
        canonical_value.encode("utf-8")
    ).hexdigest()[:12].upper()

    return f"{cls.PREFIX}-{digest}"

@classmethod
def from_configuration(
    cls,
    configuration,
    *,
    commit_sha: str | None = None,
) -> str:
    """Generate a scan ID from SecureForge configuration."""
    return cls.generate(
        application=configuration.application,
        version=configuration.version,
        profile=configuration.profile,
        commit_sha=commit_sha,
        environment=configuration.environment,
    )

@staticmethod
def _normalize(value: str | None) -> str:
    """Normalize an optional identifier component."""
    if value is None:
        return ""

    normalized = str(value).strip().lower()
    return re.sub(
        r"\s+",
        " ",
        normalized,
    )

@staticmethod
def _normalize_profile(
    profile: ScanProfile | str,
) -> str:
    """Normalize a scan profile."""
    if isinstance(profile, ScanProfile):
        return profile.value

    return str(profile).strip().lower()
```
