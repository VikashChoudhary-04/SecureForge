"""Factory for creating SecureForge scan runs."""

from **future** import annotations

from typing import Any

from secureforge.core.config import ScanConfiguration

from .identifiers import ScanIdentifier
from .models import ScanRun

class ScanRunFactory:
"""Create initialized ScanRun objects from SecureForge configuration."""

```
def __init__(
    self,
    identifier_generator: type[ScanIdentifier] = ScanIdentifier,
) -> None:
    self.identifier_generator = identifier_generator

def create(
    self,
    configuration: ScanConfiguration,
    *,
    commit_sha: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> ScanRun:
    """Create a scan run from a validated configuration."""
    scan_id = self.identifier_generator.from_configuration(
        configuration,
        commit_sha=commit_sha,
    )

    scan_metadata = dict(
        metadata or {}
    )

    scan_metadata.setdefault(
        "target_name",
        configuration.target.name,
    )

    scan_metadata.setdefault(
        "target_type",
        configuration.target.target_type.value,
    )

    return ScanRun(
        scan_id=scan_id,
        application=configuration.application,
        version=configuration.version,
        profile=configuration.profile,
        environment=configuration.environment,
        commit_sha=commit_sha,
        metadata=scan_metadata,
    )

@staticmethod
def validate_configuration(
    configuration: ScanConfiguration,
) -> None:
    """Validate configuration fields required for scan creation."""
    if not configuration.application.strip():
        raise ValueError(
            "Scan application cannot be empty."
        )

    if not configuration.version.strip():
        raise ValueError(
            "Scan version cannot be empty."
        )

    if not configuration.target.name.strip():
        raise ValueError(
            "Scan target name cannot be empty."
        )
```
