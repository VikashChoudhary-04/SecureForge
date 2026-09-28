"""Tests for SecureForge configuration loading."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from secureforge.config.loader import (
    ConfigLoadError,
    ConfigLoader,
)


def test_loader_loads_ci_profile() -> None:
    """The configuration loader resolves the CI profile."""
    loader = ConfigLoader()

    configuration = loader.load_profile("ci")

    assert configuration["profile"]["name"] == "ci"
    assert configuration["integrations"] == ["ci"]


def test_loader_profile_lookup_is_case_insensitive() -> None:
    """Profile names are normalized before loading."""
    loader = ConfigLoader()

    configuration = loader.load_profile("CI")

    assert configuration["profile"]["name"] == "ci"


def test_loader_rejects_unknown_profile() -> None:
    """Unknown profiles produce a configuration error."""
    loader = ConfigLoader()

    with pytest.raises(
        ConfigLoadError,
        match="Unknown SecureForge profile",
    ):
        loader.load_profile("does-not-exist")


def test_loader_rejects_missing_file(
    tmp_path: Path,
) -> None:
    """Missing configuration files produce a clear error."""
    loader = ConfigLoader(
        config_directory=tmp_path,
    )

    with pytest.raises(
        ConfigLoadError,
        match="does not exist",
    ):
        loader.load_profile("ci")


def test_loader_rejects_non_mapping_root(
    tmp_path: Path,
) -> None:
    """Configuration files must have a mapping as their root."""
    config_path = tmp_path / "ci.yaml"
    config_path.write_text(
        "- invalid\n- root\n",
        encoding="utf-8",
    )

    loader = ConfigLoader(
        config_directory=tmp_path,
    )

    with pytest.raises(
        ConfigLoadError,
        match="root must be a mapping",
    ):
        loader.load_profile("ci")


def test_loader_rejects_invalid_yaml(
    tmp_path: Path,
) -> None:
    """Malformed YAML produces a configuration error."""
    config_path = tmp_path / "ci.yaml"
    config_path.write_text(
        "profile:\n  name: [invalid\n",
        encoding="utf-8",
    )

    loader = ConfigLoader(
        config_directory=tmp_path,
    )

    with pytest.raises(
        ConfigLoadError,
        match="Invalid YAML",
    ):
        loader.load_profile("ci")


def test_loader_loads_arbitrary_file(
    tmp_path: Path,
) -> None:
    """The loader can load a valid arbitrary YAML file."""
    config_path = tmp_path / "custom.yaml"

    configuration = {
        "profile": {
            "name": "custom",
        },
        "integrations": [
            "ci",
        ],
    }

    config_path.write_text(
        yaml.safe_dump(configuration),
        encoding="utf-8",
    )

    loader = ConfigLoader(
        config_directory=tmp_path,
    )

    loaded = loader.load_file(config_path)

    assert loaded == configuration
