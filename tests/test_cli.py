"""Tests for the SecureForge command-line interface."""

from typer.testing import CliRunner

from secureforge.cli.main import app


runner = CliRunner()


def test_help_command_succeeds() -> None:
    """Verify the CLI exposes help successfully."""
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "SecureForge" in result.stdout


def test_version_command_succeeds() -> None:
    """Verify the CLI reports its installed version."""
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert "SecureForge 0.1.0" in result.stdout


def test_scan_accepts_quick_profile() -> None:
    """Verify the quick scan profile is accepted."""
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            "quick",
        ],
    )

    assert result.exit_code == 0
    assert "Profile: quick" in result.stdout


def test_scan_accepts_standard_profile() -> None:
    """Verify the standard scan profile is accepted."""
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            "standard",
        ],
    )

    assert result.exit_code == 0
    assert "Profile: standard" in result.stdout


def test_scan_accepts_full_profile() -> None:
    """Verify the full scan profile is accepted."""
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            "full",
        ],
    )

    assert result.exit_code == 0
    assert "Profile: full" in result.stdout


def test_scan_rejects_invalid_profile() -> None:
    """Verify unsupported scan profiles return a CLI error."""
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            "invalid",
        ],
    )

    assert result.exit_code == 2
    assert "unsupported profile" in result.stdout


def test_report_accepts_json_format() -> None:
    """Verify JSON reporting format is accepted."""
    result = runner.invoke(
        app,
        [
            "report",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert "Report format: json" in result.stdout


def test_report_accepts_html_format() -> None:
    """Verify HTML reporting format is accepted."""
    result = runner.invoke(
        app,
        [
            "report",
            "--format",
            "html",
        ],
    )

    assert result.exit_code == 0
    assert "Report format: html" in result.stdout


def test_report_rejects_invalid_format() -> None:
    """Verify unsupported report formats return a CLI error."""
    result = runner.invoke(
        app,
        [
            "report",
            "--format",
            "xml",
        ],
    )

    assert result.exit_code == 2
    assert "unsupported report format" in result.stdout


def test_policy_command_succeeds() -> None:
    """Verify the current policy command is exposed."""
    result = runner.invoke(
        app,
        ["policy"],
    )

    assert result.exit_code == 0
    assert "SecureForge Policy Evaluation" in result.stdout


def test_regression_command_succeeds() -> None:
    """Verify the regression command is exposed."""
    result = runner.invoke(
        app,
        ["regression"],
    )

    assert result.exit_code == 0
    assert "SecureForge Security Regression" in result.stdout


def test_validate_requires_finding_id() -> None:
    """Verify finding validation requires a finding identifier."""
    result = runner.invoke(
        app,
        ["validate"],
    )

    assert result.exit_code != 0


def test_validate_accepts_finding_id() -> None:
    """Verify finding validation accepts a finding identifier."""
    result = runner.invoke(
        app,
        [
            "validate",
            "--finding",
            "SF-0001",
        ],
    )

    assert result.exit_code == 0
    assert "Finding: SF-0001" in result.stdout
