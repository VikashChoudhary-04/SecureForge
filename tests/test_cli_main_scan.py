```python id="k5r9cw"
"""Tests for the SecureForge scan CLI command."""

from pathlib import Path

from typer.testing import CliRunner

from secureforge.cli.main import app
from secureforge.config.runtime_builder import (
    RuntimeConfigurationError,
)
from secureforge.core.config.models import ScanProfile


runner = CliRunner()


def test_scan_command_help() -> None:
    """Expose scan configuration options through the CLI."""
    result = runner.invoke(
        app,
        [
            "scan",
            "--help",
        ],
    )

    assert result.exit_code == 0
    assert "--profile" in result.stdout
    assert "--target" in result.stdout
    assert "--source-path" in result.stdout
    assert "--scan-id" in result.stdout
    assert "--application" in result.stdout
    assert "--version-label" in result.stdout
    assert "--commit-sha" in result.stdout
    assert "--environment" in result.stdout
    assert "--output" in result.stdout
    assert "--scan-storage" in result.stdout


def test_report_command_help() -> None:
    """Expose the report command through the CLI."""
    result = runner.invoke(
        app,
        [
            "report",
            "--help",
        ],
    )

    assert result.exit_code == 0
    assert "--json" in result.stdout
    assert "--html" in result.stdout


def test_version_command() -> None:
    """Expose the SecureForge version through the CLI."""
    result = runner.invoke(
        app,
        [
            "--version",
        ],
    )

    assert result.exit_code == 0
    assert "SecureForge" in result.stdout


def test_invalid_profile_is_rejected() -> None:
    """Reject an unsupported scan profile."""
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            "invalid-profile",
        ],
    )

    assert result.exit_code != 0


def test_scan_command_default_profile_is_standard(
    monkeypatch,
    sample_scan_result,
) -> None:
    """Use the standard profile when none is supplied."""
    captured: dict[str, object] = {}

    class FakeService:
        def run(
            self,
            configuration,
        ):
            captured["configuration"] = (
                configuration
            )
            return sample_scan_result

    monkeypatch.setattr(
        "secureforge.cli.main.build_scan_command_service",
        lambda: FakeService(),
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "--target",
            "http://127.0.0.1:5000",
            "--scan-id",
            "cli-test",
        ],
    )

    assert result.exit_code in {
        0,
        1,
    }

    configuration = captured[
        "configuration"
    ]

    assert (
        configuration.scan_id
        == "cli-test"
    )
    assert (
        configuration.profile
        == ScanProfile.STANDARD
    )
    assert (
        configuration.target
        == "http://127.0.0.1:5000"
    )


def test_scan_command_accepts_quick_profile(
    monkeypatch,
    sample_scan_result,
) -> None:
    """Accept the quick scan profile."""
    captured: dict[str, object] = {}

    class FakeService:
        def run(
            self,
            configuration,
        ):
            captured["configuration"] = (
                configuration
            )
            return sample_scan_result

    monkeypatch.setattr(
        "secureforge.cli.main.build_scan_command_service",
        lambda: FakeService(),
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            "quick",
        ],
    )

    assert result.exit_code in {
        0,
        1,
    }

    configuration = captured[
        "configuration"
    ]

    assert (
        configuration.profile
        == ScanProfile.QUICK
    )


def test_scan_command_accepts_full_profile(
    monkeypatch,
    sample_scan_result,
) -> None:
    """Accept the full scan profile."""
    captured: dict[str, object] = {}

    class FakeService:
        def run(
            self,
            configuration,
        ):
            captured["configuration"] = (
                configuration
            )
            return sample_scan_result

    monkeypatch.setattr(
        "secureforge.cli.main.build_scan_command_service",
        lambda: FakeService(),
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            "full",
        ],
    )

    assert result.exit_code in {
        0,
        1,
    }

    configuration = captured[
        "configuration"
    ]

    assert (
        configuration.profile
        == ScanProfile.FULL
    )


def test_scan_command_displays_result(
    monkeypatch,
    sample_scan_result,
) -> None:
    """Display important scan and release results."""
    class FakeService:
        def run(
            self,
            configuration,
        ):
            return sample_scan_result

    monkeypatch.setattr(
        "secureforge.cli.main.build_scan_command_service",
        lambda: FakeService(),
    )

    result = runner.invoke(
        app,
        [
            "scan",
        ],
    )

    assert result.exit_code in {
        0,
        1,
    }

    assert "Scan ID:" in result.stdout
    assert "Status:" in result.stdout
    assert "Findings:" in result.stdout
    assert "Risk Score:" in result.stdout
    assert "Highest Severity:" in result.stdout
    assert "Release Decision:" in result.stdout
    assert "Release Allowed:" in result.stdout
    assert "Security Report:" in result.stdout
    assert "HTML Report:" in result.stdout
    assert "Persisted Scan:" in result.stdout


def test_scan_command_passes_source_path(
    monkeypatch,
    sample_scan_result,
    tmp_path: Path,
) -> None:
    """Pass a source directory into the scan configuration."""
    captured: dict[str, object] = {}

    class FakeService:
        def run(
            self,
            configuration,
        ):
            captured["configuration"] = (
                configuration
            )
            return sample_scan_result

    monkeypatch.setattr(
        "secureforge.cli.main.build_scan_command_service",
        lambda: FakeService(),
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "--source-path",
            str(tmp_path),
        ],
    )

    assert result.exit_code in {
        0,
        1,
    }

    configuration = captured[
        "configuration"
    ]

    assert (
        configuration.source_path
        == tmp_path
    )


def test_scan_command_passes_release_metadata(
    monkeypatch,
    sample_scan_result,
    tmp_path: Path,
) -> None:
    """Pass release metadata into the scan service."""
    captured: dict[str, object] = {}

    class FakeService:
        def run(
            self,
            configuration,
        ):
            captured["configuration"] = (
                configuration
            )
            return sample_scan_result

    monkeypatch.setattr(
        "secureforge.cli.main.build_scan_command_service",
        lambda: FakeService(),
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "--application",
            "securecommerce",
            "--version-label",
            "1.2.0",
            "--commit-sha",
            "abc123",
            "--environment",
            "lab",
            "--output",
            str(tmp_path / "reports"),
            "--scan-storage",
            str(tmp_path / "scans"),
        ],
    )

    assert result.exit_code in {
        0,
        1,
    }

    configuration = captured[
        "configuration"
    ]

    assert (
        configuration.application
        == "securecommerce"
    )
    assert (
        configuration.version
        == "1.2.0"
    )
    assert (
        configuration.commit_sha
        == "abc123"
    )
    assert (
        configuration.environment
        == "lab"
    )
    assert (
        configuration.output_directory
        == tmp_path / "reports"
    )
    assert (
        configuration.scan_storage_directory
        == tmp_path / "scans"
    )


def test_scan_command_handles_configuration_error(
    monkeypatch,
) -> None:
    """Return exit code 2 for configuration errors."""
    class FakeService:
        def run(
            self,
            configuration,
        ):
            raise RuntimeConfigurationError(
                "invalid scan configuration"
            )

    monkeypatch.setattr(
        "secureforge.cli.main.build_scan_command_service",
        lambda: FakeService(),
    )

    result = runner.invoke(
        app,
        [
            "scan",
        ],
    )

    assert result.exit_code == 2
    assert (
        "Configuration error:"
        in result.stdout
    )


def test_scan_command_handles_unexpected_error(
    monkeypatch,
) -> None:
    """Return exit code 2 for unexpected scan errors."""
    class FakeService:
        def run(
            self,
            configuration,
        ):
            raise RuntimeError(
                "unexpected failure"
            )

    monkeypatch.setattr(
        "secureforge.cli.main.build_scan_command_service",
        lambda: FakeService(),
    )

    result = runner.invoke(
        app,
        [
            "scan",
        ],
    )

    assert result.exit_code == 2
    assert (
        "Scan failed:"
        in result.stdout
    )
```
