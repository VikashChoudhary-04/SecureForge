"""Tests for the SecureForge scan CLI command."""

from unittest.mock import Mock

from typer.testing import CliRunner

from secureforge.cli.main import app
from secureforge.core.release_gate.models import (
ReleaseGateStatus,
)

runner = CliRunner()

def test_scan_command_runs_successfully(
monkeypatch,
) -> None:
"""Return success when the release is allowed."""
scan_result = Mock()

```
scan_result.execution.scan_id = "scan-001"
scan_result.execution.status.value = "completed"
scan_result.execution.warnings = []
scan_result.execution.errors = []

scan_result.findings = []

scan_result.pipeline.risk.score = 12.5
scan_result.pipeline.risk.highest_severity.value = "low"

scan_result.release_status = (
    ReleaseGateStatus.ALLOWED.value
)
scan_result.release_allowed = True
scan_result.release_blocked = False
scan_result.pipeline.regression_gate = None

service = Mock()
service.run.return_value = scan_result

monkeypatch.setattr(
    "secureforge.cli.main.build_scan_command_service",
    lambda: service,
)

result = runner.invoke(
    app,
    [
        "scan",
        "--profile",
        "quick",
        "--target",
        "http://127.0.0.1:5000",
        "--scan-id",
        "scan-001",
    ],
)

assert result.exit_code == 0
assert "Scan ID: scan-001" in result.stdout
assert "Status: completed" in result.stdout
assert "Findings: 0" in result.stdout
assert "Risk Score: 12.5" in result.stdout
assert "Release Allowed: True" in result.stdout

service.run.assert_called_once()
```

def test_scan_command_returns_one_when_release_is_blocked(
monkeypatch,
) -> None:
"""Return a non-zero exit code when the release is blocked."""
scan_result = Mock()

```
scan_result.execution.scan_id = "scan-002"
scan_result.execution.status.value = "completed"
scan_result.execution.warnings = []
scan_result.execution.errors = []

scan_result.findings = []

scan_result.pipeline.risk.score = 85.0
scan_result.pipeline.risk.highest_severity.value = "high"

scan_result.release_status = (
    ReleaseGateStatus.BLOCKED.value
)
scan_result.release_allowed = False
scan_result.release_blocked = True

scan_result.pipeline.regression_gate = None

service = Mock()
service.run.return_value = scan_result

monkeypatch.setattr(
    "secureforge.cli.main.build_scan_command_service",
    lambda: service,
)

result = runner.invoke(
    app,
    [
        "scan",
        "--profile",
        "standard",
        "--target",
        "http://127.0.0.1:5000",
        "--scan-id",
        "scan-002",
    ],
)

assert result.exit_code == 1
assert "Scan ID: scan-002" in result.stdout
assert "Release Allowed: False" in result.stdout
assert (
    "Release Decision: "
    f"{ReleaseGateStatus.BLOCKED.value}"
    in result.stdout
)
```

def test_scan_command_reports_regression_gate(
monkeypatch,
) -> None:
"""Display the regression-gate status when available."""
scan_result = Mock()

```
scan_result.execution.scan_id = "scan-003"
scan_result.execution.status.value = "completed"
scan_result.execution.warnings = []
scan_result.execution.errors = []

scan_result.findings = []

scan_result.pipeline.risk.score = 0.0
scan_result.pipeline.risk.highest_severity.value = "info"

scan_result.release_status = (
    ReleaseGateStatus.BLOCKED.value
)
scan_result.release_allowed = False
scan_result.release_blocked = True

scan_result.pipeline.regression_gate.status = (
    "failed"
)

service = Mock()
service.run.return_value = scan_result

monkeypatch.setattr(
    "secureforge.cli.main.build_scan_command_service",
    lambda: service,
)

result = runner.invoke(
    app,
    [
        "scan",
        "--target",
        "http://127.0.0.1:5000",
    ],
)

assert result.exit_code == 1
assert "Regression Gate: failed" in (
    result.stdout
)
```

def test_scan_command_reports_configuration_error(
monkeypatch,
) -> None:
"""Return a configuration error with exit code two."""
from secureforge.config.runtime_builder import (
RuntimeConfigurationError,
)

```
service = Mock()

service.run.side_effect = (
    RuntimeConfigurationError(
        "Scan target must not be empty."
    )
)

monkeypatch.setattr(
    "secureforge.cli.main.build_scan_command_service",
    lambda: service,
)

result = runner.invoke(
    app,
    [
        "scan",
        "--target",
        " ",
    ],
)

assert result.exit_code == 2
assert (
    "Configuration error: "
    "Scan target must not be empty."
    in result.stdout
)
```

def test_scan_command_accepts_source_path(
monkeypatch,
tmp_path,
) -> None:
"""Pass the source path through the CLI configuration."""
source_path = tmp_path / "source"
source_path.mkdir()

```
scan_result = Mock()

scan_result.execution.scan_id = "scan-004"
scan_result.execution.status.value = "completed"
scan_result.execution.warnings = []
scan_result.execution.errors = []

scan_result.findings = []
scan_result.pipeline.risk.score = 0.0
scan_result.pipeline.risk.highest_severity.value = "info"
scan_result.release_status = "allowed"
scan_result.release_allowed = True
scan_result.release_blocked = False
scan_result.pipeline.regression_gate = None

service = Mock()
service.run.return_value = scan_result

monkeypatch.setattr(
    "secureforge.cli.main.build_scan_command_service",
    lambda: service,
)

result = runner.invoke(
    app,
    [
        "scan",
        "--profile",
        "full",
        "--target",
        "http://127.0.0.1:5000",
        "--source-path",
        str(source_path),
    ],
)

assert result.exit_code == 0

configuration = (
    service.run.call_args.args[0]
)

assert configuration.scan_id == "cli-scan"
assert configuration.profile.value == "full"
assert configuration.target == (
    "http://127.0.0.1:5000"
)
assert configuration.source_path == source_path
```
