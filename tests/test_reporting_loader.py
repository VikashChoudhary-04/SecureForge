```python id="h3q8lz"
"""Tests for SecureForge security report loading."""

from pathlib import Path

import pytest

from secureforge.reporting import (
    SecurityReportLoadError,
    SecurityReportLoader,
    load_security_report,
)


def test_report_loader_loads_valid_report(
    tmp_path: Path,
    sample_security_report,
) -> None:
    """Load a valid persisted security report."""
    path = (
        tmp_path
        / "security-report.json"
    )

    path.write_text(
        sample_security_report.model_dump_json(
            indent=2
        ),
        encoding="utf-8",
    )

    loader = SecurityReportLoader()

    loaded = loader.load(path)

    assert loaded == sample_security_report


def test_report_loader_rejects_missing_file(
    tmp_path: Path,
) -> None:
    """Reject a report path that does not exist."""
    path = (
        tmp_path
        / "missing.json"
    )

    loader = SecurityReportLoader()

    with pytest.raises(
        SecurityReportLoadError,
        match="not found",
    ):
        loader.load(path)


def test_report_loader_rejects_directory(
    tmp_path: Path,
) -> None:
    """Reject a directory supplied as a report path."""
    loader = SecurityReportLoader()

    with pytest.raises(
        SecurityReportLoadError,
        match="not a file",
    ):
        loader.load(tmp_path)


def test_report_loader_rejects_invalid_json(
    tmp_path: Path,
) -> None:
    """Reject malformed JSON."""
    path = (
        tmp_path
        / "invalid.json"
    )

    path.write_text(
        "{invalid",
        encoding="utf-8",
    )

    loader = SecurityReportLoader()

    with pytest.raises(
        SecurityReportLoadError,
        match="invalid JSON",
    ):
        loader.load(path)


def test_report_loader_rejects_non_object_json(
    tmp_path: Path,
) -> None:
    """Reject valid JSON that is not an object."""
    path = (
        tmp_path
        / "list.json"
    )

    path.write_text(
        "[]",
        encoding="utf-8",
    )

    loader = SecurityReportLoader()

    with pytest.raises(
        SecurityReportLoadError,
        match="JSON object",
    ):
        loader.load(path)


def test_report_loader_rejects_invalid_schema(
    tmp_path: Path,
) -> None:
    """Reject JSON that does not satisfy the report schema."""
    path = (
        tmp_path
        / "invalid-schema.json"
    )

    path.write_text(
        '{"unexpected": "value"}',
        encoding="utf-8",
    )

    loader = SecurityReportLoader()

    with pytest.raises(
        SecurityReportLoadError,
        match="schema validation",
    ):
        loader.load(path)


def test_load_security_report_helper(
    tmp_path: Path,
    sample_security_report,
) -> None:
    """Verify the convenience loading function."""
    path = (
        tmp_path
        / "security-report.json"
    )

    path.write_text(
        sample_security_report.model_dump_json(),
        encoding="utf-8",
    )

    loaded = load_security_report(path)

    assert loaded == sample_security_report
```
