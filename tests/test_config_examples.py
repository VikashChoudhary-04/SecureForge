"""Tests for SecureForge configuration examples."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(**file**).resolve().parents[1]
CONFIG_DIR = ROOT / "secureforge" / "config"

def load_yaml(path: Path) -> dict:
"""Load a YAML configuration file."""
with path.open("r", encoding="utf-8") as file:
data = yaml.safe_load(file)

assert isinstance(data, dict)

return data

def test_default_config_exists() -> None:
"""The default configuration should exist."""
path = CONFIG_DIR / "default.yaml"

assert path.is_file()

def test_quick_config_exists() -> None:
"""The quick configuration should exist."""
path = CONFIG_DIR / "quick.yaml"

assert path.is_file()

def test_standard_config_exists() -> None:
"""The standard configuration should exist."""
path = CONFIG_DIR / "standard.yaml"

assert path.is_file()

def test_full_config_exists() -> None:
"""The full configuration should exist."""
path = CONFIG_DIR / "full.yaml"

assert path.is_file()

def test_securecommerce_config_exists() -> None:
"""The SecureCommerce example should exist."""
path = (
CONFIG_DIR
/ "examples"
/ "securecommerce.yaml"
)

assert path.is_file()

def test_full_lab_config_exists() -> None:
"""The full lab example should exist."""
path = (
CONFIG_DIR
/ "examples"
/ "full-lab.yaml"
)

assert path.is_file()

def test_default_config_structure() -> None:
"""The default configuration should contain core sections."""
config = load_yaml(
CONFIG_DIR / "default.yaml"
)

assert config["project"]["name"] == "securecommerce"
assert config["project"]["application"] == "SecureCommerce"
assert config["scan"]["profile"] == "standard"

assert "target" in config
assert "integrations" in config
assert "output" in config
assert "logging" in config

def test_quick_config_uses_quick_profile() -> None:
"""The quick configuration should use the quick profile."""
config = load_yaml(
CONFIG_DIR / "quick.yaml"
)

assert config["scan"]["profile"] == "quick"

assert set(config["integrations"]) == {
    "sast",
    "sca",
    "secrets",
}

def test_standard_config_uses_standard_profile() -> None:
"""The standard configuration should contain standard integrations."""
config = load_yaml(
CONFIG_DIR / "standard.yaml"
)

assert config["scan"]["profile"] == "standard"

assert set(config["integrations"]) == {
    "sast",
    "sca",
    "secrets",
    "api",
    "dast",
    "container",
}

def test_full_config_uses_full_profile() -> None:
"""The full configuration should declare all integrations."""
config = load_yaml(
CONFIG_DIR / "full.yaml"
)

assert config["scan"]["profile"] == "full"

assert set(config["integrations"]) == {
    "sast",
    "sca",
    "secrets",
    "api",
    "dast",
    "container",
    "iac",
    "nessus",
    "nmap",
    "manual",
}

def test_securecommerce_config_contains_application_targets() -> None:
"""SecureCommerce should expose the targets required by standard scans."""
config = load_yaml(
CONFIG_DIR
/ "examples"
/ "securecommerce.yaml"
)

target = config["target"]

assert target["base_url"] == "http://localhost:5000"
assert target["api_base_url"] == (
    "http://localhost:5000/api"
)
assert target["openapi_url"] == (
    "http://localhost:5000/openapi.json"
)
assert target["source_path"] == (
    "./vulnerable-app/securecommerce"
)
assert target["container_image"] == (
    "securecommerce:latest"
)

def test_securecommerce_config_references_policy_and_requirements() -> None:
"""SecureCommerce should reference the policy and requirement catalogs."""
config = load_yaml(
CONFIG_DIR
/ "examples"
/ "securecommerce.yaml"
)

assert config["policy"]["path"] == (
    "./policies/default.yaml"
)

assert config["requirements"]["path"] == (
    "./requirements/security-requirements.yaml"
)

def test_full_lab_config_contains_full_targets() -> None:
"""The full lab configuration should expose all target types."""
config = load_yaml(
CONFIG_DIR
/ "examples"
/ "full-lab.yaml"
)

target = config["target"]

assert target["base_url"] == "http://localhost:5000"
assert target["api_base_url"] == (
    "http://localhost:5000/api"
)
assert target["openapi_url"] == (
    "http://localhost:5000/openapi.json"
)
assert target["source_path"] == (
    "./vulnerable-app/securecommerce"
)
assert target["container_image"] == (
    "securecommerce:latest"
)
assert target["iac_path"] == (
    "./vulnerable-app/securecommerce/infra"
)
assert target["network_target"] == "127.0.0.1"
assert target["evidence_path"] == "./evidence"

def test_full_lab_config_declares_all_integrations() -> None:
"""The full lab configuration should declare every integration."""
config = load_yaml(
CONFIG_DIR
/ "examples"
/ "full-lab.yaml"
)

integrations = config["integrations"]

expected = {
    "sast",
    "sca",
    "secrets",
    "api",
    "dast",
    "container",
    "iac",
    "nessus",
    "nmap",
    "manual",
}

assert set(integrations) == expected

def test_full_lab_config_references_policy_and_requirements() -> None:
"""The full lab should use the shared policy and requirements."""
config = load_yaml(
CONFIG_DIR
/ "examples"
/ "full-lab.yaml"
)

assert config["policy"]["path"] == (
    "./policies/default.yaml"
)

assert config["requirements"]["path"] == (
    "./requirements/security-requirements.yaml"
)

def test_integration_commands_are_strings_when_defined() -> None:
"""Configured integration commands should be strings."""
for filename in (
"default.yaml",
"quick.yaml",
"standard.yaml",
"full.yaml",
):
config = load_yaml(CONFIG_DIR / filename)

    for name, integration in config["integrations"].items():
        if "command" in integration:
            assert isinstance(
                integration["command"],
                str,
            ), name

def test_output_paths_are_defined() -> None:
"""Every configuration should define report output paths."""
for path in (
CONFIG_DIR / "default.yaml",
CONFIG_DIR / "quick.yaml",
CONFIG_DIR / "standard.yaml",
CONFIG_DIR / "full.yaml",
CONFIG_DIR
/ "examples"
/ "securecommerce.yaml",
CONFIG_DIR
/ "examples"
/ "full-lab.yaml",
):
config = load_yaml(path)

    output = config["output"]

    assert output["directory"]
    assert output["json"]
    assert output["html"]
