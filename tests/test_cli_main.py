"""Tests for the main SecureForge CLI."""

from __future__ import annotations

from typer.testing import CliRunner

from secureforge import __version__
from secureforge.cli.main import app

runner = CliRunner()

def test_version_command():
"""CLI should display the SecureForge version."""
result = runner.invoke(
app,
[
"--version",
],
)


assert result.exit_code == 0
assert (
    f"SecureForge {__version__}"
    in result.stdout
)


def test_scan_accepts_quick_profile():
"""Scan command should accept the quick profile."""
result = runner.invoke(
app,
[
"scan",
"--profile",
"quick",
],
)


assert result.exit_code == 0
assert (
    "Selected profile: quick"
    in result.stdout
)


def test_scan_accepts_standard_profile():
"""Scan command should accept the standard profile."""
result = runner.invoke(
app,
[
"scan",
"--profile",
"standard",
],
)


assert result.exit_code == 0
assert (
    "Selected profile: standard"
    in result.stdout
)


def test_scan_accepts_full_profile():
"""Scan command should accept the full profile."""
result = runner.invoke(
app,
[
"scan",
"--profile",
"full",
],
)


assert result.exit_code == 0
assert (
    "Selected profile: full"
    in result.stdout
)


def test_scan_rejects_invalid_profile():
"""Scan command should reject an invalid profile."""
result = runner.invoke(
app,
[
"scan",
"--profile",
"invalid",
],
)


assert result.exit_code != 0


def test_report_command_is_available():
"""Report command should be exposed."""
result = runner.invoke(
app,
[
"report",
],
)


assert result.exit_code == 0
assert (
    "Report generation command"
    in result.stdout
)


def test_regression_command_is_available():
"""Regression command group should be exposed."""
result = runner.invoke(
app,
[
"regression",
"--help",
],
)


assert result.exit_code == 0
assert "run" in result.stdout


def test_regression_run_command_is_available():
"""Regression run command should be exposed."""
result = runner.invoke(
app,
[
"regression",
"run",
"--help",
],
)

assert result.exit_code == 0
assert "--suite" in result.stdout
assert "--base-url" in result.stdout
assert "--source-root" in result.stdout
assert "--infrastructure-root" in result.stdout
