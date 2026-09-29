"""Tests for SecureForge runtime configuration."""

from __future__ import annotations

from pathlib import Path

import pytest

from secureforge.config.runtime import (
RuntimeConfigurationError,
load_runtime_configuration,
)

def write_config(
tmp_path: Path,
content: str,
) -> Path:
"""Write a temporary YAML configuration."""
path = tmp_path / "secureforge.yaml"
path.write_text(
content,
encoding="utf-8",
)
return path

def test_load_runtime_configuration(
tmp_path: Path,
) -> None:
"""A valid configuration should load successfully."""
path = write_config(
tmp_path,
"""
project:
name: securecommerce
application: SecureCommerce

scan:
profile: standard

target:
base_url: http://localhost:5000

integrations:
sast:
enabled: true
command: "sast-scanner --source {source_path} --format json"

output:
directory: ./reports
""",
)

configuration = load_runtime_configuration(path)

assert configuration.path == path
assert configuration.project["name"] == "securecommerce"
assert configuration.project["application"] == "SecureCommerce"
assert configuration.profile == "standard"
assert configuration.target["base_url"] == (
    "http://localhost:5000"
)

def test_runtime_configuration_sections(
tmp_path: Path,
) -> None:
"""Configuration sections should be accessible through properties."""
path = write_config(
tmp_path,
"""
project:
name: securecommerce
application: SecureCommerce

scan:
profile: quick

target:
source_path: ./app

integrations:
sast:
enabled: true

policy:
path: ./policies/default.yaml

requirements:
path: ./requirements/security-requirements.yaml

output:
directory: ./reports

logging:
level: INFO
""",
)

configuration = load_runtime_configuration(path)

assert configuration.scan["profile"] == "quick"
assert configuration.target["source_path"] == "./app"
assert configuration.policy["path"] == (
    "./policies/default.yaml"
)
assert configuration.requirements["path"] == (
    "./requirements/security-requirements.yaml"
)
assert configuration.output["directory"] == "./reports"
assert configuration.logging["level"] == "INFO"

def test_profile_is_normalized(
tmp_path: Path,
) -> None:
"""Profile names should be normalized to lowercase."""
path = write_config(
tmp_path,
"""
project:
name: securecommerce
application: SecureCommerce

scan:
profile: STANDARD

integrations:
sast:
enabled: true
""",
)

configuration = load_runtime_configuration(path)

assert configuration.profile == "standard"

def test_integration_returns_configuration(
tmp_path: Path,
) -> None:
"""Individual integration configuration should be accessible."""
path = write_config(
tmp_path,
"""
project:
name: securecommerce
application: SecureCommerce

scan:
profile: quick

integrations:
sast:
enabled: true
command: "custom-sast"

secrets:
enabled: false
""",
)

configuration = load_runtime_configuration(path)

assert configuration.integration("sast") == {
    "enabled": True,
    "command": "custom-sast",
}

assert configuration.integration("missing") == {}

def test_enabled_integrations(
tmp_path: Path,
) -> None:
"""Only explicitly enabled integrations should be returned."""
path = write_config(
tmp_path,
"""
project:
name: securecommerce
application: SecureCommerce

scan:
profile: standard

integrations:
sast:
enabled: true

sca:
enabled: false

secrets:
enabled: true
""",
)

configuration = load_runtime_configuration(path)

assert configuration.enabled_integrations() == [
    "sast",
    "secrets",
]

def test_missing_project_name_fails(
tmp_path: Path,
) -> None:
"""A missing project name should fail validation."""
path = write_config(
tmp_path,
"""
project:
application: SecureCommerce

scan:
profile: quick

integrations:
sast:
enabled: true
""",
)

with pytest.raises(
    RuntimeConfigurationError,
    match="project.name is required",
):
    load_runtime_configuration(path)

def test_missing_application_fails(
tmp_path: Path,
) -> None:
"""A missing application name should fail validation."""
path = write_config(
tmp_path,
"""
project:
name: securecommerce

scan:
profile: quick

integrations:
sast:
enabled: true
""",
)

with pytest.raises(
    RuntimeConfigurationError,
    match="project.application is required",
):
    load_runtime_configuration(path)

def test_missing_profile_fails(
tmp_path: Path,
) -> None:
"""A missing scan profile should fail validation."""
path = write_config(
tmp_path,
"""
project:
name: securecommerce
application: SecureCommerce

scan: {}

integrations:
sast:
enabled: true
""",
)

with pytest.raises(
    RuntimeConfigurationError,
    match="scan.profile is required",
):
    load_runtime_configuration(path)

def test_missing_integrations_fails(
tmp_path: Path,
) -> None:
"""At least one integration configuration is required."""
path = write_config(
tmp_path,
"""
project:
name: securecommerce
application: SecureCommerce

scan:
profile: quick

integrations: {}
""",
)

with pytest.raises(
    RuntimeConfigurationError,
    match="At least one integration must be configured",
):
    load_runtime_configuration(path)

def test_invalid_integration_configuration_fails(
tmp_path: Path,
) -> None:
"""Integration configuration must be a mapping."""
path = write_config(
tmp_path,
"""
project:
name: securecommerce
application: SecureCommerce

scan:
profile: quick

integrations:
sast: true
""",
)

with pytest.raises(
    RuntimeConfigurationError,
    match="Integration 'sast' configuration must be a mapping",
):
    load_runtime_configuration(path)

def test_invalid_section_type_fails(
tmp_path: Path,
) -> None:
"""A configuration section with the wrong type should fail."""
path = write_config(
tmp_path,
"""
project:
name: securecommerce
application: SecureCommerce

scan:
profile: quick

target: invalid

integrations:
sast:
enabled: true
""",
)

configuration = load_runtime_configuration(path)

with pytest.raises(
    RuntimeConfigurationError,
    match="Configuration section 'target' must be a mapping",
):
    _ = configuration.target

def test_missing_file_fails(
tmp_path: Path,
) -> None:
"""A missing configuration file should fail clearly."""
path = tmp_path / "missing.yaml"

with pytest.raises(
    RuntimeConfigurationError,
    match="Configuration file does not exist",
):
    load_runtime_configuration(path)

def test_invalid_yaml_fails(
tmp_path: Path,
) -> None:
"""Malformed YAML should produce a configuration error."""
path = write_config(
tmp_path,
"""
project:
name: securecommerce
application: SecureCommerce
invalid: [this is not valid yaml
""",
)

with pytest.raises(
    RuntimeConfigurationError,
    match="Invalid YAML configuration",
):
    load_runtime_configuration(path)

def test_non_mapping_root_fails(
tmp_path: Path,
) -> None:
"""The YAML root must be a mapping."""
path = write_config(
tmp_path,
"""

* securecommerce
* standard
  """,
  )

  with pytest.raises(
  RuntimeConfigurationError,
  match="root configuration value must be a mapping",
  ):
  load_runtime_configuration(path)

def test_existing_example_config_loads() -> None:
"""The SecureCommerce example should load successfully."""
root = Path(**file**).resolve().parents[1]

path = (
    root
    / "secureforge"
    / "config"
    / "examples"
    / "securecommerce.yaml"
)

configuration = load_runtime_configuration(path)

assert configuration.project["application"] == (
    "SecureCommerce"
)
assert configuration.profile == "standard"

def test_full_lab_example_loads() -> None:
"""The full lab example should load successfully."""
root = Path(**file**).resolve().parents[1]

path = (
    root
    / "secureforge"
    / "config"
    / "examples"
    / "full-lab.yaml"
)

configuration = load_runtime_configuration(path)

assert configuration.profile == "full"
assert "nessus" in configuration.integrations
assert "nmap" in configuration.integrations
assert "manual" in configuration.integrations
