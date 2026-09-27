"""Tests for the SecureForge regression service."""

from **future** import annotations

from pathlib import Path

from secureforge.regression import (
RegressionService,
RegressionServiceConfiguration,
RegressionStatus,
)

def write_suite(
path: Path,
) -> None:
"""Write a minimal regression suite."""
path.write_text(
"""
suite:
id: service-test
name: Service Regression Test

tests:

* id: SECRET-001
  name: Secret Detection
  security_requirement: SF-SECRET-001
  description: Detect hardcoded secrets.
  objective: Prevent secret leakage.
  target: source
  method: STATIC
  expected_result: No active secret.
  failure_condition: Active secret detected.
  """,
  encoding="utf-8",
  )

def test_service_runs_regression_suite(
tmp_path: Path,
):
"""Service should execute the configured regression suite."""
suite_path = (
tmp_path
/ "suite.yaml"
)

```
write_suite(suite_path)

source_root = (
    tmp_path
    / "source"
)
source_root.mkdir()

(
    source_root
    / "application.py"
).write_text(
    "VALUE = 'safe'\n",
    encoding="utf-8",
)

service = RegressionService()

result = service.run(
    RegressionServiceConfiguration(
        suite_path=suite_path,
        source_root=source_root,
    )
)

assert result.suite_id == "service-test"
assert result.name == "Service Regression Test"
assert result.status == RegressionStatus.PASSED
assert result.total == 1
assert result.passed == 1
assert result.failed == 0
assert result.errors == 0
assert result.skipped == 0
```

def test_service_propagates_failed_regression(
tmp_path: Path,
):
"""Service should preserve failed regression results."""
suite_path = (
tmp_path
/ "suite.yaml"
)

```
write_suite(suite_path)

source_root = (
    tmp_path
    / "source"
)
source_root.mkdir()

(
    source_root
    / "secrets.py"
).write_text(
    'API_KEY = "sk-lab-example-123456789"\n',
    encoding="utf-8",
)

service = RegressionService()

result = service.run(
    RegressionServiceConfiguration(
        suite_path=suite_path,
        source_root=source_root,
    )
)

assert result.status == RegressionStatus.FAILED
assert result.total == 1
assert result.passed == 0
assert result.failed == 1
assert result.errors == 0
```

def test_service_accepts_custom_runtime_configuration(
tmp_path: Path,
):
"""Service should preserve custom runtime configuration."""
suite_path = (
tmp_path
/ "suite.yaml"
)

```
write_suite(suite_path)

source_root = (
    tmp_path
    / "source"
)
source_root.mkdir()

(
    source_root
    / "application.py"
).write_text(
    "VALUE = 'safe'\n",
    encoding="utf-8",
)

service = RegressionService()

configuration = RegressionServiceConfiguration(
    suite_path=suite_path,
    base_url="http://localhost:9000",
    timeout=15.0,
    source_root=source_root,
)

result = service.run(
    configuration
)

assert result.status == RegressionStatus.PASSED
assert result.total == 1
```

def test_service_configuration_is_immutable(
tmp_path: Path,
):
"""Service configuration should be immutable."""
suite_path = (
tmp_path
/ "suite.yaml"
)

```
configuration = RegressionServiceConfiguration(
    suite_path=suite_path
)

try:
    configuration.timeout = 10.0
except Exception as exc:
    error = exc
else:
    error = None

assert error is not None
```
