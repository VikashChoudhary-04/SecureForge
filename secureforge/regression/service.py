"""Service layer for SecureForge regression testing."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .models import RegressionSuiteResult
from .runner import (
RegressionRunConfiguration,
RegressionRunner,
)

@dataclass(frozen=True)
class RegressionServiceConfiguration:
"""Configuration for a SecureForge regression service run."""

```
suite_path: Path
base_url: str = "http://127.0.0.1:5000"
timeout: float = 5.0
source_root: Path | None = None
infrastructure_root: Path | None = None
```

class RegressionService:
"""Provide a stable programmatic interface for regression testing."""

```
def __init__(
    self,
    *,
    runner: RegressionRunner | None = None,
) -> None:
    self.runner = (
        runner
        if runner is not None
        else RegressionRunner()
    )

def run(
    self,
    configuration: RegressionServiceConfiguration,
) -> RegressionSuiteResult:
    """Execute the configured regression suite."""
    runner_configuration = (
        RegressionRunConfiguration(
            suite_path=configuration.suite_path,
            base_url=configuration.base_url,
            timeout=configuration.timeout,
            source_root=configuration.source_root,
            infrastructure_root=(
                configuration.infrastructure_root
            ),
        )
    )

    return self.runner.run(
        runner_configuration
    )
```

def build_regression_service() -> RegressionService:
"""Build the default regression service."""
return RegressionService()
