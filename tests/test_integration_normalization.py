"""Tests for integration-backed normalization adapters and registry factory."""

from __future__ import annotations

from typing import Any

import pytest

from secureforge.core.normalization import (
    NormalizationResult,
    RawEvidence,
)
from secureforge.integrations.base import SecurityIntegration
from secureforge.integrations.normalization import (
    IntegrationNormalizationAdapter,
    build_default_normalization_registry,
)
from secureforge.integrations.registry_factory import (
    build_default_registry,
)


class FakeNormalizationIntegration(SecurityIntegration):
    """Minimal integration used to verify adapter delegation."""

    name = "fake"
    integration_name = "fake"

    def __init__(self) -> None:
        self.received_evidence: RawEvidence | None = None

    def normalize(
        self,
        evidence: RawEvidence,
    ) -> NormalizationResult:
        self.received_evidence = evidence

        return NormalizationResult(
            source=self.integration_name,
            findings=[
                {
                    "finding_id": "FAKE-001",
                    "title": "Fake finding",
                }
            ],
        )


def test_integration_normalization_adapter_delegates_to_integration() -> None:
    """The adapter should delegate RawEvidence to the integration."""
    integration = FakeNormalizationIntegration()

    adapter = IntegrationNormalizationAdapter(
        integration=integration,
    )

    evidence = RawEvidence(
        source="fake",
        raw_data={
            "result": "test",
        },
    )

    result = adapter.parse(evidence)

    assert integration.received_evidence is evidence
    assert result.source == "fake"
    assert result.findings == [
        {
            "finding_id": "FAKE-001",
            "title": "Fake finding",
        }
    ]


def test_integration_normalization_adapter_uses_integration_name() -> None:
    """The adapter source should match the wrapped integration."""
    integration = FakeNormalizationIntegration()

    adapter = IntegrationNormalizationAdapter(
        integration=integration,
    )

    assert adapter.source_name == "fake"


def test_integration_normalization_adapter_rejects_wrong_source() -> None:
    """The adapter should enforce the normalization source contract."""
    integration = FakeNormalizationIntegration()

    adapter = IntegrationNormalizationAdapter(
        integration=integration,
    )

    evidence = RawEvidence(
        source="other",
        raw_data={},
    )

    with pytest.raises(
        ValueError,
        match="Expected source 'fake', received 'other'",
    ):
        adapter.parse(evidence)


def test_integration_normalization_adapter_rejects_invalid_result() -> None:
    """The adapter should reject an integration returning the wrong type."""

    class InvalidIntegration(FakeNormalizationIntegration):
        def normalize(
            self,
            evidence: RawEvidence,
        ) -> Any:
            del evidence
            return []

    integration = InvalidIntegration()

    adapter = IntegrationNormalizationAdapter(
        integration=integration,
    )

    evidence = RawEvidence(
        source="fake",
        raw_data={},
    )

    with pytest.raises(
        TypeError,
        match="must return NormalizationResult",
    ):
        adapter.parse(evidence)


def test_default_normalization_registry_contains_generic_integrations() -> None:
    """Generic integrations should be registered for normalization."""
    registry = build_default_normalization_registry()

    assert registry.sources() == [
        "api",
        "container",
        "dast",
        "iac",
        "nmap",
        "sast",
        "sca",
        "secrets",
    ]


def test_default_normalization_registry_excludes_specialized_integrations() -> None:
    """Legacy/specialized normalizers should not enter the generic pipeline."""
    registry = build_default_normalization_registry()

    assert not registry.contains("manual")
    assert not registry.contains("nessus")


def test_default_normalization_registry_reuses_integration_instances() -> None:
    """Adapters should wrap the instances from the supplied integration registry."""
    integration_registry = build_default_registry()
    normalization_registry = build_default_normalization_registry(
        integration_registry=integration_registry,
    )

    for source in (
        "api",
        "container",
        "dast",
        "iac",
        "nmap",
        "sast",
        "sca",
        "secrets",
    ):
        adapter = normalization_registry.require(source)

        assert isinstance(
            adapter,
            IntegrationNormalizationAdapter,
        )
        assert adapter.integration is (
            integration_registry.require(source)
        )


def test_default_normalization_registry_builds_independent_instances() -> None:
    """Separate registry builds should not share integration instances."""
    first = build_default_normalization_registry()
    second = build_default_normalization_registry()

    for source in (
        "api",
        "container",
        "dast",
        "iac",
        "nmap",
        "sast",
        "sca",
        "secrets",
    ):
        first_adapter = first.require(source)
        second_adapter = second.require(source)

        assert isinstance(
            first_adapter,
            IntegrationNormalizationAdapter,
        )
        assert isinstance(
            second_adapter,
            IntegrationNormalizationAdapter,
        )
        assert first_adapter.integration is not second_adapter.integration
