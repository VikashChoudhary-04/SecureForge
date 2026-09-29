"""Tests for loading and validating persisted security reports."""

import json
from pathlib import Path

import pytest

from secureforge.reporting import (
    SecurityReport,
    SecurityReportLoadError,
    SecurityReportLoader,
    load_security_report,
)


def test_loader_loads_valid_security_report(
    sample_security_report,
    tmp_path: Path,
) -> None:
    """Load a valid persisted security report."""
    path = tmp_path / "security-report.json"

    path.write_text(
        json.dumps(
            sample_security_report.model_dump(
                mode="json"
            ),
            indent=2,
        ),
        encoding="utf-8",
    )

    loader = SecurityReportLoader()

    report = loader.load(path)

    assert isinstance(
        report,
        SecurityReport,
    )

    assert report == sample_security_report


def test_loader_function_loads_valid_security_report(
    sample_security_report,
    tmp_path: Path,
) -> None:
    """Load a valid report through the convenience function."""
    path = tmp_path / "security-report.json"

    path.write_text(
        json.dumps(
            sample_security_report.model_dump(
                mode="json"
            )
        ),
        encoding="utf-8",
    )

    report = load_security_report(path)

    assert isinstance(
        report,
        SecurityReport,
    )

    assert report.release.application == (
        sample_security_report.release.application
    )


def test_loader_rejects_missing_file(
    tmp_path: Path,
) -> None:
    """Reject a report path that does not exist."""
    path = tmp_path / "missing.json"

    loader = SecurityReportLoader()

    with pytest.raises(
        SecurityReportLoadError,
        match="Security report not found",
    ):
        loader.load(path)


def test_loader_rejects_directory(
    tmp_path: Path,
) -> None:
    """Reject a directory supplied as a report path."""
    directory = tmp_path / "reports"
    directory.mkdir()

    loader = SecurityReportLoader()

    with pytest.raises(
        SecurityReportLoadError,
        match="Security report path is not a file",
    ):
        loader.load(directory)


def test_loader_rejects_invalid_json(
    tmp_path: Path,
) -> None:
    """Reject malformed JSON."""
    path = tmp_path / "security-report.json"

    path.write_text(
        "{invalid-json",
        encoding="utf-8",
    )

    loader = SecurityReportLoader()

    with pytest.raises(
        SecurityReportLoadError,
        match="contains invalid JSON",
    ):
        loader.load(path)


def test_loader_rejects_non_object_json(
    tmp_path: Path,
) -> None:
    """Reject JSON documents whose root is not an object."""
    path = tmp_path / "security-report.json"

    path.write_text(
        json.dumps(["not", "an", "object"]),
        encoding="utf-8",
    )

    loader = SecurityReportLoader()

    with pytest.raises(
        SecurityReportLoadError,
        match="must contain a JSON object",
    ):
        loader.load(path)


def test_loader_rejects_invalid_report_schema(
    tmp_path: Path,
) -> None:
    """Reject JSON that does not satisfy the report schema."""
    path = tmp_path / "security-report.json"

    path.write_text(
        json.dumps(
            {
                "release": {
                    "application": "securecommerce"
                }
            }
        ),
        encoding="utf-8",
    )

    loader = SecurityReportLoader()

    with pytest.raises(
        SecurityReportLoadError,
        match="failed schema validation",
    ):
        loader.load(path)


def test_loader_rejects_missing_required_report_section(
    sample_security_report,
    tmp_path: Path,
) -> None:
    """Reject a report with a required section removed."""
    payload = sample_security_report.model_dump(
        mode="json"
    )

    payload.pop("decision")

    path = tmp_path / "security-report.json"

    path.write_text(
        json.dumps(payload),
        encoding="utf-8",
    )

    loader = SecurityReportLoader()

    with pytest.raises(
        SecurityReportLoadError,
        match="failed schema validation",
    ):
        loader.load(path)
