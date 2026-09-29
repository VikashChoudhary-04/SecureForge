"""Tests for the SecureForge report command service."""

import json
from pathlib import Path

from secureforge.cli.report import (
    ReportCommandConfiguration,
    ReportCommandService,
)


def test_report_command_generates_html_from_json(
    sample_security_report,
    tmp_path: Path,
) -> None:
    """Generate an HTML report from a persisted JSON report."""
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

    service = ReportCommandService()

    configuration = ReportCommandConfiguration(
        input_path=input_path,
        output_path=output_path,
    )

    generated = service.run(
        configuration
    )

    assert generated == output_path
    assert output_path.is_file()

    html = output_path.read_text(
        encoding="utf-8"
    )

    assert html
    assert "SecureForge" in html
    assert (
        sample_security_report.release.application
        in html
    )


def test_report_command_preserves_regression_data(
    sample_security_report,
    tmp_path: Path,
) -> None:
    """Preserve regression information when rendering the report."""
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

    service = ReportCommandService()

    generated = service.run(
        ReportCommandConfiguration(
            input_path=input_path,
            output_path=output_path,
        )
    )

    assert generated == output_path

    html = output_path.read_text(
        encoding="utf-8"
    )

    if sample_security_report.regression is not None:
        assert "Regression Testing" in html

        assert (
            sample_security_report.regression.suite_id
            in html
        )

    if sample_security_report.regression_gate is not None:
        assert "Regression Gate" in html


def test_report_command_creates_parent_directory(
    sample_security_report,
    tmp_path: Path,
) -> None:
    """Create the output directory when it does not exist."""
    input_path = tmp_path / "security-report.json"
    output_path = (
        tmp_path
        / "nested"
        / "reports"
        / "security-report.html"
    )

    input_path.write_text(
        json.dumps(
            sample_security_report.model_dump(
                mode="json"
            )
        ),
        encoding="utf-8",
    )

    service = ReportCommandService()

    service.run(
        ReportCommandConfiguration(
            input_path=input_path,
            output_path=output_path,
        )
    )

    assert output_path.is_file()
    assert output_path.parent.is_dir()


def test_report_command_accepts_path_objects(
    sample_security_report,
    tmp_path: Path,
) -> None:
    """Accept pathlib paths throughout the report command."""
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

    configuration = ReportCommandConfiguration(
        input_path=Path(input_path),
        output_path=Path(output_path),
    )

    service = ReportCommandService()

    result = service.run(
        configuration
    )

    assert isinstance(
        result,
        Path,
    )

    assert result == output_path
