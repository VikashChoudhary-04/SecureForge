```python id="a9c4jw"
"""Tests for the SecureForge report CLI command."""

from pathlib import Path

from typer.testing import CliRunner

from secureforge.cli.main import app
from secureforge.reporting import (
    ReportPaths,
    SecurityReportService,
)


runner = CliRunner()


def test_report_command_regenerates_html(
    sample_security_report,
    tmp_path: Path,
) -> None:
    """Regenerate HTML from a persisted JSON report."""
    json_path = (
        tmp_path
        / "security-report.json"
    )

    initial_html_path = (
        tmp_path
        / "initial.html"
    )

    SecurityReportService().generate(
        sample_security_report,
        paths=ReportPaths(
            json_path=json_path,
            html_path=initial_html_path,
        ),
    )

    regenerated_path = (
        tmp_path
        / "regenerated.html"
    )

    result = runner.invoke(
        app,
        [
            "report",
            "--json",
            str(json_path),
            "--html",
            str(regenerated_path),
        ],
    )

    assert result.exit_code == 0
    assert (
        "JSON Report:"
        in result.stdout
    )
    assert (
        "HTML Report:"
        in result.stdout
    )
    assert regenerated_path.exists()


def test_report_command_uses_default_html_path(
    sample_security_report,
    tmp_path: Path,
) -> None:
    """Generate HTML beside the supplied JSON report."""
    json_path = (
        tmp_path
        / "security-report.json"
    )

    initial_html_path = (
        tmp_path
        / "initial.html"
    )

    SecurityReportService().generate(
        sample_security_report,
        paths=ReportPaths(
            json_path=json_path,
            html_path=initial_html_path,
        ),
    )

    result = runner.invoke(
        app,
        [
            "report",
            "--json",
            str(json_path),
        ],
    )

    expected_html = (
        tmp_path
        / "security-report.html"
    )

    assert result.exit_code == 0
    assert expected_html.exists()


def test_report_command_rejects_invalid_report(
    tmp_path: Path,
) -> None:
    """Return a non-zero exit code for an invalid report."""
    json_path = (
        tmp_path
        / "invalid.json"
    )

    json_path.write_text(
        '{"invalid": true}',
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "report",
            "--json",
            str(json_path),
        ],
    )

    assert result.exit_code == 2
    assert (
        "Report generation failed:"
        in result.stdout
    )
```
