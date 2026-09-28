"""Tests for the SecureForge deterministic CI integration."""

from __future__ import annotations

from secureforge.integrations.ci import CIIntegration
from secureforge.integrations.base import IntegrationContext


def make_context(
    *,
    environment: str = "ci",
    target: str | None = None,
) -> IntegrationContext:
    """Build a minimal integration context."""
    return IntegrationContext(
        application="SecureForge",
        environment=environment,
        target=target,
        source_path=None,
        configuration={},
    )


def test_ci_integration_supports_ci_environment() -> None:
    """CI integration supports the CI environment."""
    integration = CIIntegration()

    assert integration.supports(
        make_context(environment="ci")
    )


def test_ci_integration_supports_test_environment() -> None:
    """CI integration supports the test environment."""
    integration = CIIntegration()

    assert integration.supports(
        make_context(environment="test")
    )


def test_ci_integration_rejects_lab_environment() -> None:
    """CI integration does not run in ordinary lab environments."""
    integration = CIIntegration()

    assert not integration.supports(
        make_context(environment="lab")
    )


def test_ci_integration_generates_deterministic_finding() -> None:
    """CI integration generates synthetic security evidence."""
    integration = CIIntegration()

    result = integration.execute(
        make_context(
            environment="ci",
            target="secureforge-ci",
        )
    )

    assert result.success is True
    assert len(result.findings) == 1

    finding = result.findings[0]

    assert finding.finding_id == "CI-001"
    assert finding.source == "ci"
    assert finding.severity.value == "informational"
    assert finding.confidence.value == "high"


def test_ci_integration_marks_evidence_as_synthetic() -> None:
    """CI evidence explicitly identifies itself as synthetic."""
    integration = CIIntegration()

    result = integration.execute(
        make_context(environment="ci")
    )

    assert result.success is True
    assert result.metadata["mode"] == "synthetic"
    assert result.metadata["source"] == "secureforge-ci"
    assert "No external scanner was executed." in (
        result.metadata["note"]
    )


def test_ci_integration_rejects_unsupported_environment() -> None:
    """Unsupported environments produce an integration failure."""
    integration = CIIntegration()

    result = integration.execute(
        make_context(environment="lab")
    )

    assert result.success is False
    assert result.findings == []
    assert result.error is not None
    assert "ci or test" in result.error


def test_ci_integration_describes_itself() -> None:
    """Integration metadata identifies the CI integration."""
    integration = CIIntegration()

    description = integration.describe()

    assert description["name"] == "ci"
    assert description["type"] == "ci"
    assert description["mode"] == "synthetic"

