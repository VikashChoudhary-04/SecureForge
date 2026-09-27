"""Tests for building typed scan configuration from runtime YAML."""

from **future** import annotations

from pathlib import Path

import pytest

from secureforge.config.models import ScanProfile
from secureforge.config.runtime import (
RuntimeConfiguration,
RuntimeConfigurationError,
)
from secureforge.config.runtime_builder import (
build_scan_configuration,
)

def make_runtime(
data: dict,
tmp_path: Path,
) -> RuntimeConfiguration:
"""Create a runtime configuration for testing."""
path = tmp_path / "secureforge.yaml"

```
return RuntimeConfiguration(
    path=path,
    data=data,
)
```

def base_data() -> dict:
"""Return a minimal valid runtime configuration."""
return {
"project": {
"name": "securecommerce",
"application": "SecureCommerce",
},
"scan": {
"profile": "standard",
},
"target": {
"base_url": "http://localhost:5000",
"api_base_url": "http://localhost:5000/api",
"openapi_url": "http://localhost:5000/openapi.json",
"source_path": "./vulnerable-app/securecommerce",
},
"integrations": {
"sast": {
"enabled": True,
"command": (
"sast-scanner "
"--source {source_path} "
"--format json"
),
},
"sca": {
"enabled": False,
},
},
}

def test_build_scan_configuration(
tmp_path: Path,
) -> None:
"""A runtime configuration should become a typed scan configuration."""
runtime = make_runtime(
base_data(),
tmp_path,
)

```
configuration = build_scan_configuration(runtime)

assert configuration.profile == ScanProfile.STANDARD

assert configuration.target.base_url == (
    "http://localhost:5000"
)

assert configuration.target.api_base_url == (
    "http://localhost:5000/api"
)

assert configuration.target.openapi_url == (
    "http://localhost:5000/openapi.json"
)

assert configuration.target.source_path == (
    "./vulnerable-app/securecommerce"
)
```

def test_builds_all_target_fields(
tmp_path: Path,
) -> None:
"""All supported target fields should be transferred."""
data = base_data()

```
data["target"].update(
    {
        "container_image": "securecommerce:latest",
        "container_path": "./container",
        "iac_path": "./infra",
        "network_target": "127.0.0.1",
        "evidence_path": "./evidence",
    }
)

runtime = make_runtime(
    data,
    tmp_path,
)

configuration = build_scan_configuration(runtime)
target = configuration.target

assert target.container_image == "securecommerce:latest"
assert target.container_path == "./container"
assert target.iac_path == "./infra"
assert target.network_target == "127.0.0.1"
assert target.evidence_path == "./evidence"
```

def test_builds_integration_configuration(
tmp_path: Path,
) -> None:
"""Integration settings should be converted to typed objects."""
runtime = make_runtime(
base_data(),
tmp_path,
)

```
configuration = build_scan_configuration(runtime)

sast = configuration.integrations["sast"]

assert sast.name == "sast"
assert sast.enabled is True
assert sast.command == (
    "sast-scanner "
    "--source {source_path} "
    "--format json"
)
```

def test_disabled_integration_is_preserved(
tmp_path: Path,
) -> None:
"""Disabled integrations should remain in the configuration."""
runtime = make_runtime(
base_data(),
tmp_path,
)

```
configuration = build_scan_configuration(runtime)

sca = configuration.integrations["sca"]

assert sca.enabled is False
```

def test_integration_options_are_preserved(
tmp_path: Path,
) -> None:
"""Additional integration options should not be discarded."""
data = base_data()

```
data["integrations"]["sast"].update(
    {
        "timeout": 120,
        "severity_threshold": "medium",
    }
)

runtime = make_runtime(
    data,
    tmp_path,
)

configuration = build_scan_configuration(runtime)

options = configuration.integrations["sast"].options

assert options["timeout"] == 120
assert options["severity_threshold"] == "medium"
```

def test_quick_profile_is_supported(
tmp_path: Path,
) -> None:
"""The quick profile should map correctly."""
data = base_data()
data["scan"]["profile"] = "quick"

```
runtime = make_runtime(
    data,
    tmp_path,
)

configuration = build_scan_configuration(runtime)

assert configuration.profile == ScanProfile.QUICK
```

def test_full_profile_is_supported(
tmp_path: Path,
) -> None:
"""The full profile should map correctly."""
data = base_data()
data["scan"]["profile"] = "full"

```
runtime = make_runtime(
    data,
    tmp_path,
)

configuration = build_scan_configuration(runtime)

assert configuration.profile == ScanProfile.FULL
```

def test_profile_is_case_insensitive(
tmp_path: Path,
) -> None:
"""Profile names should remain case-insensitive."""
data = base_data()
data["scan"]["profile"] = "FULL"

```
runtime = make_runtime(
    data,
    tmp_path,
)

configuration = build_scan_configuration(runtime)

assert configuration.profile == ScanProfile.FULL
```

def test_invalid_profile_fails(
tmp_path: Path,
) -> None:
"""Unsupported profiles should raise a clear error."""
data = base_data()
data["scan"]["profile"] = "enterprise"

```
runtime = make_runtime(
    data,
    tmp_path,
)

with pytest.raises(
    RuntimeConfigurationError,
    match="Unsupported scan profile 'enterprise'",
):
    build_scan_configuration(runtime)
```

def test_invalid_integration_configuration_fails(
tmp_path: Path,
) -> None:
"""Invalid integration mappings should fail clearly."""
data = base_data()
data["integrations"]["sast"] = "invalid"

```
runtime = make_runtime(
    data,
    tmp_path,
)

with pytest.raises(
    RuntimeConfigurationError,
    match="Integration 'sast' configuration must be a mapping",
):
    build_scan_configuration(runtime)
```

def test_empty_integrations_are_supported_by_builder(
tmp_path: Path,
) -> None:
"""The builder itself should not duplicate runtime validation."""
data = base_data()
data["integrations"] = {}

```
runtime = make_runtime(
    data,
    tmp_path,
)

configuration = build_scan_configuration(runtime)

assert configuration.integrations == {}
```

def test_unknown_target_fields_are_ignored(
tmp_path: Path,
) -> None:
"""Unsupported target fields should not break typed configuration."""
data = base_data()

```
data["target"]["custom_target_metadata"] = {
    "owner": "security-team",
}

runtime = make_runtime(
    data,
    tmp_path,
)

configuration = build_scan_configuration(runtime)

assert configuration.target.base_url == (
    "http://localhost:5000"
)
```
