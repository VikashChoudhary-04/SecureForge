"""Tests for the SecureForge regression CLI."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from secureforge.regression.cli import app


runner = CliRunner()


def write_suite(
    path: Path,
) -> None:
    """Write a minimal regression suite."""
    path.write_text(
        """
suite:
  id: cli-test
  name: CLI Regression Test

tests:

  - id: SECRET-001
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


def test_cli_runs_successfully(
    tmp_path: Path,
):
    """CLI should return zero when all regressions pass."""
    suite_path = (
        tmp_path
        / "suite.yaml"
    )

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

    result = runner.invoke(
        app,
        [
            "run",
            "--suite",
            str(suite_path),
            "--source-root",
            str(source_root),
        ],
    )

    assert result.exit_code == 0
    assert "Suite: CLI Regression Test" in result.stdout
    assert "Status: PASSED" in result.stdout
    assert "Total: 1" in result.stdout
    assert "Passed: 1" in result.stdout
    assert "Failed: 0" in result.stdout
    assert "SECRET-001: PASSED" in result.stdout


def test_cli_returns_failure_for_failed_regression(
    tmp_path: Path,
):
    """CLI should return one when a regression fails."""
    suite_path = (
        tmp_path
        / "suite.yaml"
    )

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

    result = runner.invoke(
        app,
        [
            "run",
            "--suite",
            str(suite_path),
            "--source-root",
            str(source_root),
        ],
    )

    assert result.exit_code == 1
    assert "Suite: CLI Regression Test" in result.stdout
    assert "Status: FAILED" in result.stdout
    assert "Total: 1" in result.stdout
    assert "Passed: 0" in result.stdout
    assert "Failed: 1" in result.stdout
    assert "SECRET-001: FAILED" in result.stdout


def test_cli_reports_execution_error(
    tmp_path: Path,
):
    """CLI should return two when regression execution cannot start."""
    suite_path = (
        tmp_path
        / "suite.yaml"
    )

    write_suite(suite_path)

    result = runner.invoke(
        app,
        [
            "run",
            "--suite",
            str(suite_path),
        ],
    )

    assert result.exit_code == 1
    assert "Status: FAILED" not in result.stdout
    assert (
        "Regression execution error:"
        in result.stdout
        or "Regression execution error:"
        in result.stderr
    )


def test_cli_help():
    """CLI should expose the regression run command."""
    result = runner.invoke(
        app,
        [
            "--help",
        ],
    )

    assert result.exit_code == 0
    assert "run" in result.stdout
    assert "regression" in result.stdout.lower()
