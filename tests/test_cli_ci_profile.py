"""Tests for SecureForge CI-profile CLI validation."""

from __future__ import annotations

from pathlib import Path

import pytest
import typer

from secureforge.cli.main import _validate_scan_options


SOURCE_PATH = Path(".")


def test_ci_profile_accepts_ci_environment() -> None:
    """The CI profile accepts the CI environment."""
    _validate_scan_options(
        profile="ci",
        environment="ci",
        target=None,
        source_path=SOURCE_PATH,
        validate=False,
        validation_finding=[],
        validation_endpoint=[],
        validation_payload=[],
        regression=False,
    )


def test_ci_profile_accepts_test_environment() -> None:
    """The CI profile accepts the test environment."""
    _validate_scan_options(
        profile="ci",
        environment="test",
        target=None,
        source_path=SOURCE_PATH,
        validate=False,
        validation_finding=[],
        validation_endpoint=[],
        validation_payload=[],
        regression=False,
    )


def test_ci_profile_rejects_lab_environment() -> None:
    """The CI profile rejects an ordinary lab environment."""
    with pytest.raises(typer.BadParameter):
        _validate_scan_options(
            profile="ci",
            environment="lab",
            target=None,
            source_path=SOURCE_PATH,
            validate=False,
            validation_finding=[],
            validation_endpoint=[],
            validation_payload=[],
            regression=False,
        )


def test_ci_profile_rejects_active_validation() -> None:
    """The deterministic CI profile does not perform active validation."""
    with pytest.raises(typer.BadParameter):
        _validate_scan_options(
            profile="ci",
            environment="ci",
            target="http://localhost:5000",
            source_path=None,
            validate=True,
            validation_finding=[],
            validation_endpoint=[],
            validation_payload=[],
            regression=False,
        )


def test_ci_profile_rejects_regression_option() -> None:
    """The deterministic CI profile does not run regressions."""
    with pytest.raises(typer.BadParameter):
        _validate_scan_options(
            profile="ci",
            environment="ci",
            target=None,
            source_path=SOURCE_PATH,
            validate=False,
            validation_finding=[],
            validation_endpoint=[],
            validation_payload=[],
            regression=True,
        )


def test_invalid_profile_is_rejected() -> None:
    """Unknown profiles are rejected."""
    with pytest.raises(typer.BadParameter):
        _validate_scan_options(
            profile="unknown",
            environment="ci",
            target=None,
            source_path=SOURCE_PATH,
            validate=False,
            validation_finding=[],
            validation_endpoint=[],
            validation_payload=[],
            regression=False,
        )
