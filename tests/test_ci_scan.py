"""End-to-end tests for the SecureForge CI scan profile."""

from __future__ import annotations

from pathlib import Path

from secureforge.config.factory import create_runtime


def test_ci_profile_runs_through_secureforge_pipeline(
    tmp_path: Path,
) -> None:
    """The CI profile executes through the complete scan pipeline."""
    runtime = create_runtime(
        profile="ci",
        target=None,
        source_path=Path("."),
    )

    result = runtime.orchestrator.run(
        scan_id="ci-test",
        profile="ci",
        target=None,
        source_path=Path("."),
        application="SecureForge",
        version="test",
        commit_sha="test-commit",
        environment="ci",
    )

    assert result.scan_id == "ci-test"
    assert result.application == "SecureForge"
    assert result.pipeline is not None

    assert len(result.pipeline.findings) == 1

    finding = result.pipeline.findings[0]

    assert finding.finding_id == "CI-001"
    assert finding.source == "ci"

    assert result.pipeline.release_gate is not None
    assert result.pipeline.release_gate.release_allowed is True
    assert result.pipeline.release_gate.status == "passed"


def test_ci_profile_does_not_require_external_scanner_commands(
    tmp_path: Path,
) -> None:
    """The deterministic CI profile does not execute external scanners."""
    runtime = create_runtime(
        profile="ci",
        target=None,
        source_path=tmp_path,
    )

    result = runtime.orchestrator.run(
        scan_id="ci-no-tools",
        profile="ci",
        target=None,
        source_path=tmp_path,
        application="SecureForge",
        version="test",
        commit_sha=None,
        environment="ci",
    )

    assert result.pipeline.release_allowed is True

    findings = result.pipeline.findings

    assert len(findings) == 1
    assert findings[0].finding_id == "CI-001"


def test_ci_profile_produces_pipeline_dictionary(
    tmp_path: Path,
) -> None:
    """The CI pipeline result can be serialized."""
    runtime = create_runtime(
        profile="ci",
        target=None,
        source_path=tmp_path,
    )

    result = runtime.orchestrator.run(
        scan_id="ci-serialization",
        profile="ci",
        target=None,
        source_path=tmp_path,
        application="SecureForge",
        version="test",
        commit_sha="abc123",
        environment="ci",
    )

    data = result.pipeline.to_dict()

    assert "findings" in data
    assert "risk" in data
    assert "policy" in data
    assert "release_gate" in data

    assert data["findings"][0]["finding_id"] == "CI-001"
    assert data["release_gate"]["release_allowed"] is True
