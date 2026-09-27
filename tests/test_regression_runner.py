"""Tests for the SecureForge regression runner."""

from **future** import annotations

from pathlib import Path

import pytest

from secureforge.regression import (
RegressionRunConfiguration,
RegressionRunner,
RegressionStatus,
)

def write_suite(
path: Path,
) -> None:
"""Write a minimal regression suite."""
path.write_text(
"""
suite:
id: securecommerce-test
name: SecureCommerce Test Suite

tests:

* id: SECRET-001
  name: Secret Detection Regression
  security_requirement: SF-SECRET-001
  description: Detect hardcoded secrets.
  objective: Prevent secret leakage.
  target: source
  method: STATIC
  expected_result: No active secret detected.
  failure_condition: Active secret detected.

* id: MISCONFIG-001
  name: Infrastructure Regression
  security_requirement: SF-IAC-001
  description: Validate infrastructure security.
  objective: Prevent insecure infrastructure.
  target: infrastructure
  method: STATIC
  expected_result: Secure infrastructure.
  failure_condition: Insecure infrastructure.
  """,
  encoding="utf-8",
  )

def test_runner_executes_loaded_suite(
tmp_path: Path,
):
"""Runner should load and execute a complete suite."""
suite_path = (
tmp_path
/ "regression-tests.yaml"
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
    """
```

def health():
return "ok"
""",
encoding="utf-8",
)

```
infrastructure_root = (
    tmp_path
    / "infra"
)
infrastructure_root.mkdir()

(
    infrastructure_root
    / "secure.tf"
).write_text(
    """
```

resource "null_resource" "secure_application" {
triggers = {
host = "127.0.0.1"
}
}

resource "null_resource" "encrypted_storage" {
triggers = {
encryption = "enabled"
access     = "private"
}
}

resource "null_resource" "least_privilege_role" {
triggers = {
permissions = "read-write-required-resources-only"
}
}
""",
encoding="utf-8",
)

```
runner = RegressionRunner()

result = runner.run(
    RegressionRunConfiguration(
        suite_path=suite_path,
        source_root=source_root,
        infrastructure_root=infrastructure_root,
    )
)

assert result.suite_id == "securecommerce-test"
assert result.name == "SecureCommerce Test Suite"
assert result.status == RegressionStatus.PASSED
assert result.total == 2
assert result.passed == 2
assert result.failed == 0
assert result.errors == 0
assert result.skipped == 0
```

def test_runner_reports_secret_regression_failure(
tmp_path: Path,
):
"""Runner should propagate a failed secret regression."""
suite_path = (
tmp_path
/ "regression-tests.yaml"
)

```
suite_path.write_text(
    """
```

suite:
id: secret-test
name: Secret Test

tests:

* id: SECRET-001
  name: Secret Detection
  security_requirement: SF-SECRET-001
  description: Detect secrets.
  objective: Prevent secrets.
  target: source
  method: STATIC
  expected_result: No active secret.
  failure_condition: Active secret detected.
  """,
  encoding="utf-8",
  )

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

  runner = RegressionRunner()

  result = runner.run(
  RegressionRunConfiguration(
  suite_path=suite_path,
  source_root=source_root,
  )
  )

  assert result.status == RegressionStatus.FAILED
  assert result.total == 1
  assert result.passed == 0
  assert result.failed == 1
  assert result.errors == 0

  regression_result = result.results[0]

  assert regression_result.test_id == "SECRET-001"
  assert regression_result.status == RegressionStatus.FAILED
  assert regression_result.security_requirement == (
  "SF-SECRET-001"
  )

def test_runner_reports_configuration_error(
tmp_path: Path,
):
"""Runner should surface missing suite configuration."""
runner = RegressionRunner()

```
configuration = RegressionRunConfiguration(
    suite_path=(
        tmp_path
        / "missing.yaml"
    )
)

with pytest.raises(
    FileNotFoundError
):
    runner.run(configuration)
```

def test_runner_uses_custom_base_url(
tmp_path: Path,
):
"""Runner should pass the configured target URL to the executor."""
suite_path = (
tmp_path
/ "regression-tests.yaml"
)

```
suite_path.write_text(
    """
```

suite:
id: custom-target
name: Custom Target

tests:

* id: SECRET-001
  name: Secret Detection
  security_requirement: SF-SECRET-001
  description: Detect secrets.
  objective: Prevent secrets.
  target: source
  method: STATIC
  expected_result: No active secret.
  failure_condition: Active secret detected.
  """,
  encoding="utf-8",
  )

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

  runner = RegressionRunner()

  result = runner.run(
  RegressionRunConfiguration(
  suite_path=suite_path,
  base_url="http://localhost:9000",
  timeout=10.0,
  source_root=source_root,
  )
  )

  assert result.status == RegressionStatus.PASSED
  assert result.results[0].test_id == "SECRET-001"
