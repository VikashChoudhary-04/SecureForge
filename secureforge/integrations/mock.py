"""Deterministic mock security integration for SecureForge tests and CI."""

from __future__ import annotations

import json

from secureforge.core.config import ScanConfiguration
from secureforge.core.normalization.models import NormalizationResult
from secureforge.core.scan.models import RawEvidence

from .base import SecurityIntegration


class MockSecurityIntegration(SecurityIntegration):
    """Produce deterministic security evidence without external tools."""

    integration_name = "mock"
    display_name = "Mock Security Scanner"

    def __init__(
        self,
        *,
        findings: list[dict[str, object]] | None = None,
    ) -> None:
        super().__init__(
            version="1.0",
            metadata={
                "purpose": "deterministic-ci-verification",
                "external_tool": False,
            },
        )
        self._findings = findings or []

    def build_command(
        self,
        configuration: ScanConfiguration,
    ) -> list[str]:
        """Return a deterministic command representation."""
        del configuration

        return [
            "secureforge-mock",
            "--format",
            "json",
        ]

    def normalize(
        self,
        evidence: RawEvidence,
    ) -> NormalizationResult:
        """Normalize deterministic mock evidence."""
        payload = evidence.raw_data

        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                payload = {}

        if not isinstance(payload, dict):
            payload = {}

        findings = payload.get("findings", [])

        if not isinstance(findings, list):
            findings = []

        return NormalizationResult(
            integration=self.integration_name,
            findings=findings,
            metadata={
                "source": self.integration_name,
                "deterministic": True,
            },
        )

    def create_evidence(
        self,
        configuration: ScanConfiguration,
    ) -> RawEvidence:
        """Create deterministic evidence for a CI verification run."""
        del configuration

        return RawEvidence(
            integration=self.integration_name,
            raw_data=json.dumps(
                {
                    "findings": self._findings,
                    "metadata": {
                        "deterministic": True,
                        "external_tool": False,
                    },
                }
            ),
            metadata={
                "source": self.integration_name,
                "deterministic": True,
            },
        )

    def supports_target(
        self,
        configuration: ScanConfiguration,
    ) -> bool:
        """Return whether the mock integration can run."""
        del configuration
        return True


__all__ = [
    "MockSecurityIntegration",
]
