"""Tests for the SecureForge scan command service."""

from pathlib import Path
from unittest.mock import Mock

import pytest

from secureforge.cli.scan import (
ScanCommandConfiguration,
ScanCommandService,
)
from secureforge.config.runtime_builder import (
RuntimeConfigurationError,
)
from secureforge.core.config.models import ScanProfile

def test_scan_command_service_runs_orchestrator(
tmp_path: Path,
) -> None:
"""Run a configured scan through the orchestrator."""
orchestrator = Mock()

```
expected_result = object()

orchestrator.run.return_value = expected_result

service = ScanCommandService(
    orchestrator=orchestrator
)

source_path = tmp_path / "source"
source_path.mkdir()

configuration = ScanCommandConfiguration(
    scan_id="scan-001",
    profile=ScanProfile.STANDARD,
    target="http://127.0.0.1:5000",
    source_path=source_path,
)

result = service.run(
    configuration
)

assert result is expected_result

orchestrator.run.assert_called_once_with(
    scan_id="scan-001",
    profile="standard",
    target="http://127.0.0.1:5000",
    source_path=str(source_path),
)
```

def test_scan_command_service_rejects_empty_target() -> None:
"""Reject a scan configuration with an empty target."""
service = ScanCommandService(
orchestrator=Mock()
)

```
configuration = ScanCommandConfiguration(
    scan_id="scan-002",
    profile=ScanProfile.QUICK,
    target="   ",
)

with pytest.raises(
    RuntimeConfigurationError,
    match="Scan target must not be empty",
):
    service.run(
        configuration
    )
```

def test_scan_command_service_rejects_missing_source_path(
tmp_path: Path,
) -> None:
"""Reject a source path that does not exist."""
service = ScanCommandService(
orchestrator=Mock()
)

```
missing_path = (
    tmp_path / "does-not-exist"
)

configuration = ScanCommandConfiguration(
    scan_id="scan-003",
    profile=ScanProfile.FULL,
    target="http://127.0.0.1:5000",
    source_path=missing_path,
)

with pytest.raises(
    RuntimeConfigurationError,
    match="Source path does not exist",
):
    service.run(
        configuration
    )
```

def test_scan_command_configuration_defaults_source_path() -> None:
"""Keep source path optional."""
configuration = ScanCommandConfiguration(
scan_id="scan-004",
profile=ScanProfile.STANDARD,
target="http://127.0.0.1:5000",
)

```
assert configuration.source_path is None
```
