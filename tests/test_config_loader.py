"""Tests for the SecureForge configuration loader."""

from pathlib import Path

import pytest

from secureforge.core.config import (
ScanConfiguration,
ScanProfile,
TargetType,
)
from secureforge.core.config.loader import ConfigurationLoader

def build_configuration() -> ScanConfiguration:
"""Create a representative SecureForge configuration."""
return ScanConfiguration(
application="SecureCommerce",
version="1.0.0",
profile=ScanProfile.STANDARD,
environment="lab",
target={
"name": "SecureCommerce",
"target_type": TargetType.WEB_AND_API,
"base_url": "http://localhost:8000",
"api_base_url": "http://localhost:8000/api",
"openapi_url": "http://localhost:8000/openapi.json",
"source_path": "vulnerable-app/securecommerce",
},
tools=[
{
"name": "semgrep",
"enabled": True,
"executable": "semgrep",
"timeout_seconds": 120,
},
],
)

def test_load_data_returns_scan_configuration() -> None:
"""Verify dictionary data becomes a typed configuration."""
loader = ConfigurationLoader()

```
configuration = loader.load_data(
    {
        "application": "SecureCommerce",
        "version": "1.0.0",
        "profile": "standard",
        "environment": "lab",
        "target": {
            "name": "SecureCommerce",
            "target_type": "web_and_api",
            "base_url": "http://localhost:8000",
            "api_base_url": "http://localhost:8000/api",
        },
    }
)

assert isinstance(configuration, ScanConfiguration)
assert configuration.application == "SecureCommerce"
assert configuration.profile == ScanProfile.STANDARD
assert configuration.target.target_type == TargetType.WEB_AND_API
```

def test_load_file_reads_yaml_configuration(
tmp_path: Path,
) -> None:
"""Verify YAML configuration files are loaded correctly."""
configuration_file = tmp_path / "secureforge.yaml"

```
configuration_file.write_text(
    """
```

application: SecureCommerce
version: "1.0.0"
profile: standard
environment: lab
target:
name: SecureCommerce
target_type: web_and_api
base_url: http://localhost:8000
api_base_url: http://localhost:8000/api
openapi_url: http://localhost:8000/openapi.json
""",
encoding="utf-8",
)

```
configuration = ConfigurationLoader().load_file(
    configuration_file
)

assert configuration.application == "SecureCommerce"
assert configuration.version == "1.0.0"
assert configuration.profile == ScanProfile.STANDARD
assert configuration.target.base_url == "http://localhost:8000"
```

def test_load_file_accepts_string_path(
tmp_path: Path,
) -> None:
"""Verify configuration paths can be supplied as strings."""
configuration_file = tmp_path / "secureforge.yaml"

```
configuration_file.write_text(
    """
```

application: SecureCommerce
version: "1.0.0"
target:
name: SecureCommerce
target_type: web
base_url: http://localhost:8000
""",
encoding="utf-8",
)

```
configuration = ConfigurationLoader().load_file(
    str(configuration_file)
)

assert configuration.application == "SecureCommerce"
```

def test_missing_configuration_file_is_rejected(
tmp_path: Path,
) -> None:
"""Verify missing configuration files raise a useful error."""
missing_file = tmp_path / "missing.yaml"

```
with pytest.raises(
    FileNotFoundError,
    match="was not found",
):
    ConfigurationLoader().load_file(missing_file)
```

def test_directory_is_rejected_as_configuration_file(
tmp_path: Path,
) -> None:
"""Verify directories cannot be loaded as configuration files."""
configuration_directory = tmp_path / "config"
configuration_directory.mkdir()

```
with pytest.raises(
    ValueError,
    match="is not a file",
):
    ConfigurationLoader().load_file(
        configuration_directory
    )
```

def test_empty_yaml_file_is_rejected(
tmp_path: Path,
) -> None:
"""Verify an empty YAML file is rejected."""
configuration_file = tmp_path / "empty.yaml"
configuration_file.write_text(
"",
encoding="utf-8",
)

```
with pytest.raises(
    ValueError,
    match="Configuration file is empty",
):
    ConfigurationLoader().load_file(configuration_file)
```

def test_non_mapping_yaml_is_rejected(
tmp_path: Path,
) -> None:
"""Verify YAML lists cannot be used as configuration roots."""
configuration_file = tmp_path / "invalid.yaml"

```
configuration_file.write_text(
    """
```

* SecureCommerce
* standard
  """,
  encoding="utf-8",
  )

  with pytest.raises(
  ValueError,
  match="must contain a YAML mapping",
  ):
  ConfigurationLoader().load_file(configuration_file)

def test_malformed_yaml_is_rejected(
tmp_path: Path,
) -> None:
"""Verify malformed YAML produces a clear error."""
configuration_file = tmp_path / "malformed.yaml"

```
configuration_file.write_text(
    """
```

application: SecureCommerce
target:
name: SecureCommerce
invalid-indentation
""",
encoding="utf-8",
)

```
with pytest.raises(
    ValueError,
    match="Invalid YAML configuration",
):
    ConfigurationLoader().load_file(configuration_file)
```

def test_invalid_configuration_schema_is_rejected() -> None:
"""Verify missing required configuration fields are rejected."""
loader = ConfigurationLoader()

```
with pytest.raises(
    ValueError,
    match="Invalid SecureForge configuration",
):
    loader.load_data(
        {
            "application": "SecureCommerce",
            "version": "1.0.0",
        }
    )
```

def test_invalid_profile_is_rejected() -> None:
"""Verify unsupported scan profiles fail validation."""
loader = ConfigurationLoader()

```
with pytest.raises(
    ValueError,
    match="Invalid SecureForge configuration",
):
    loader.load_data(
        {
            "application": "SecureCommerce",
            "version": "1.0.0",
            "profile": "enterprise",
            "target": {
                "name": "SecureCommerce",
                "target_type": "web",
                "base_url": "http://localhost:8000",
            },
        }
    )
```

def test_dump_data_returns_json_compatible_dictionary() -> None:
"""Verify configuration can be converted to serializable data."""
configuration = build_configuration()

```
data = ConfigurationLoader().dump_data(configuration)

assert isinstance(data, dict)
assert data["application"] == "SecureCommerce"
assert data["version"] == "1.0.0"
assert data["profile"] == "standard"
assert data["target"]["target_type"] == "web_and_api"
```

def test_save_file_writes_yaml(
tmp_path: Path,
) -> None:
"""Verify validated configuration can be written to YAML."""
configuration = build_configuration()
output_file = tmp_path / "output" / "secureforge.yaml"

```
ConfigurationLoader().save_file(
    configuration,
    output_file,
)

assert output_file.exists()

content = output_file.read_text(
    encoding="utf-8"
)

assert "application: SecureCommerce" in content
assert "profile: standard" in content
assert "target_type: web_and_api" in content
```

def test_saved_configuration_can_be_loaded_again(
tmp_path: Path,
) -> None:
"""Verify configuration serialization supports round trips."""
configuration = build_configuration()
configuration_file = tmp_path / "secureforge.yaml"

```
loader = ConfigurationLoader()

loader.save_file(
    configuration,
    configuration_file,
)

loaded = loader.load_file(
    configuration_file
)

assert loaded.application == configuration.application
assert loaded.version == configuration.version
assert loaded.profile == configuration.profile
assert loaded.environment == configuration.environment
assert loaded.target == configuration.target
assert loaded.tools == configuration.tools
```

def test_save_file_creates_parent_directories(
tmp_path: Path,
) -> None:
"""Verify nested output directories are created automatically."""
configuration = build_configuration()
output_file = (
tmp_path
/ "nested"
/ "config"
/ "secureforge.yaml"
)

```
ConfigurationLoader().save_file(
    configuration,
    output_file,
)

assert output_file.exists()
```

def test_load_data_rejects_none() -> None:
"""Verify None is rejected as configuration data."""
with pytest.raises(
ValueError,
match="Configuration file is empty",
):
ConfigurationLoader().load_data(None)

def test_load_data_rejects_scalar_values() -> None:
"""Verify scalar YAML roots are rejected."""
with pytest.raises(
ValueError,
match="must contain a YAML mapping",
):
ConfigurationLoader().load_data(
"SecureCommerce"
)
