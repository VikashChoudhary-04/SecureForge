"""Tests for the SecureForge report CLI command."""

import json
from pathlib import Path

from typer.testing import CliRunner

from secureforge.cli.main import app


runner = CliRunner()


def test_report_command_generates_html(
    sample_security_report,
    tmp_path: Path,
) -> None:
    """The report command should render HTML from JSON."""
    input_path = tmp_path / "security-report.json"
    output_path = tmp_path / "security-report.html"

    input_path.write_text(
        json.dumps(
            sample_security_report.model_dump(
                mode="json"
            ),
            indent=2,
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "report",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    assert output_path.is_file()

    output = output_path.read_text(
        encoding="utf-8"
    )

    assert "SecureForge" in output
    assert (
        sample_security_report.release.application
        in output
    )


def test_report_command_uses_default_output_path(
    sample_security_report,
    tmp_path: Path,
) -> None:
    """The report command should derive an output path when omitted."""
    input_path = tmp_path / "security-report.json"

    input_path.write_text(
        json.dumps(
            sample_security_report.model_dump(
                mode="json"
            )
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "report",
            "--input",
            str(input_path),
        ],
    )

    assert result.exit_code == 0

    expected_path = (
        tmp_path
        / "security-report.html"
    )

    assert expected_path.is_file()


def test_report_command_reports_output_path(
    sample_security_report,
    tmp_path: Path,
) -> None:
    """The CLI should report where the HTML file was written."""
    input_path = tmp_path / "security-report.json"
    output_path = tmp_path / "security-report.html"

    input_path.write_text(
        json.dumps(
            sample_security_report.model_dump(
                mode="json"
            )
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "report",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    assert str(output_path) in result.stdout


def test_report_command_rejects_missing_input(
    tmp_path: Path,
) -> None:
    """The CLI should return a failure for a missing report."""
    input_path = tmp_path / "missing.json"
    output_path = tmp_path / "security-report.html"

    result = runner.invoke(
        app,
        [
            "report",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code != 0
    assert not output_path.exists()


def test_report_command_rejects_invalid_json(
    tmp_path: Path,
) -> None:
    """The CLI should reject malformed report JSON."""
    input_path = tmp_path / "security-report.json"
    output_path = tmp_path / "security-report.html"

    input_path.write_text(
        "{invalid-json",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "report",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code != 0
    assert not output_path.exists()
