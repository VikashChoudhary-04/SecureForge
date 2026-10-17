"""Bridge security integrations into the SecureForge normalization pipeline."""

from __future__ import annotations

from typing import Any

from secureforge.core.normalization import (
    NormalizationAdapter,
    NormalizationRegistry,
    NormalizationResult,
    RawEvidence,
)

from .base import SecurityIntegration
from .registry import IntegrationRegistry
from .registry_factory import build_default_registry


class IntegrationNormalizationAdapter(NormalizationAdapter):
    """Adapt an existing integration normalizer to the pipeline contract."""

    def __init__(
        self,
        *,
        integration: SecurityIntegration,
    ) -> None:
        source_name = str(
            getattr(
                integration,
                "integration_name",
                integration.name,
            )
        ).strip().lower()

        super().__init__(
            source_version=getattr(
                integration,
                "version",
                None,
            )
        )

        self.integration = integration
        self.source_name = source_name

    def parse(
        self,
        raw_evidence: RawEvidence,
    ) -> NormalizationResult:
        """Delegate normalization to the wrapped integration."""
        self.validate_input(raw_evidence)

        normalize = getattr(
            self.integration,
            "normalize",
            None,
        )

        if normalize is None or not callable(normalize):
            raise TypeError(
                f"Integration '{self.source_name}' does not "
                "provide a compatible normalize() method."
            )

        result = normalize(
            raw_evidence,
        )

        if not isinstance(
            result,
            NormalizationResult,
        ):
            raise TypeError(
                f"Integration '{self.source_name}' normalize() "
                "must return NormalizationResult."
            )

        return result


_NORMALIZABLE_INTEGRATIONS = (
    "api",
    "container",
    "dast",
    "iac",
    "nmap",
    "sast",
    "sca",
    "secrets",
)


def build_default_normalization_registry(
    *,
    integration_registry: IntegrationRegistry | None = None,
) -> NormalizationRegistry:
    """Build the default registry of integration-backed normalizers."""
    integrations = (
        integration_registry
        if integration_registry is not None
        else build_default_registry()
    )

    registry = NormalizationRegistry()

    for source in _NORMALIZABLE_INTEGRATIONS:
        integration = integrations.require(source)

        registry.register(
            IntegrationNormalizationAdapter(
                integration=integration,
            )
        )

    return registry


__all__ = [
    "IntegrationNormalizationAdapter",
    "build_default_normalization_registry",
]
