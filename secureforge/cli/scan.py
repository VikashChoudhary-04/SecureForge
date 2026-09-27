"""SecureForge scan command service."""

from **future** import annotations

from dataclasses import dataclass
from pathlib import Path

from secureforge.config.runtime_builder import (
RuntimeConfigurationError,
)
from secureforge.core.config.models import ScanProfile
from secureforge.core.scan import (
ScanOrchestrator,
ScanRunner,
SecurityScanResult,
)
from secureforge.integrations.registry_factory import (
build_default_integration_registry,
)

@dataclass(frozen=True)
class ScanCommandConfiguration:
"""Configuration supplied to the SecureForge scan command."""

```
scan_id: str
profile: ScanProfile
target: str
source_path: Path | None = None
```

class ScanCommandService:
"""Execute a SecureForge scan from CLI configuration."""

```
def __init__(
    self,
    *,
    orchestrator: ScanOrchestrator | None = None,
) -> None:
    if orchestrator is not None:
        self.orchestrator = orchestrator
        return

    registry = (
        build_default_integration_registry()
    )

    runner = ScanRunner(
        registry=registry
    )

    self.orchestrator = ScanOrchestrator(
        runner=runner
    )

def run(
    self,
    configuration: ScanCommandConfiguration,
) -> SecurityScanResult:
    """Execute a configured security scan."""
    if not configuration.target.strip():
        raise RuntimeConfigurationError(
            "Scan target must not be empty."
        )

    if (
        configuration.source_path is not None
        and not configuration.source_path.exists()
    ):
        raise RuntimeConfigurationError(
            "Source path does not exist: "
            f"{configuration.source_path}"
        )

    return self.orchestrator.run(
        scan_id=configuration.scan_id,
        profile=configuration.profile.value,
        target=configuration.target,
        source_path=(
            str(configuration.source_path)
            if configuration.source_path is not None
            else None
        ),
    )
```

def build_scan_command_service() -> ScanCommandService:
"""Build the default scan command service."""
return ScanCommandService()
