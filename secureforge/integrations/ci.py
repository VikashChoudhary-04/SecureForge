from __future__ import annotations

from dataclasses import dataclass

from secureforge.core.findings.models import (
    Confidence,
    Finding,
    InformationalSeverity,
)
from secureforge.integrations.base import (
    IntegrationContext,
    IntegrationResult,
    SecurityIntegration,
)


@dataclass
class CIIntegrationResult(IntegrationResult):
    """Result returned by the deterministic CI integration."""

    error: str | None = None


class CIIntegration(SecurityIntegration):
    """Generate deterministic CI evidence without an external scanner."""

    name = "ci"
    integration_name = "ci"

    def supports(self, context: IntegrationContext) -> bool:
        return context.environment.lower() in {"ci", "test"}

    def execute(self, context: IntegrationContext) -> CIIntegrationResult:
        if not self.supports(context):
            return CIIntegrationResult(
                integration=self.name,
                success=False,
                error="CI integration only supports ci or test environments.",
                metadata={
                    "mode": "synthetic",
                    "source": "secureforge-ci",
                },
            )

        target = context.target or "secureforge-ci"
        finding = Finding(
            finding_id="CI-001",
            title="SecureForge CI verification executed",
            source="ci",
            asset=target,
            application=context.application,
            severity=InformationalSeverity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            description=(
                "SecureForge executed its deterministic CI verification "
                "integration."
            ),
            impact=(
                "This evidence confirms that the SecureForge CI integration "
                "was invoked."
            ),
            remediation=(
                "No remediation is required for this synthetic CI evidence."
            ),
        )

        return CIIntegrationResult(
            integration=self.name,
            success=True,
            findings=[finding],
            metadata={
                "mode": "synthetic",
                "source": "secureforge-ci",
                "note": (
                    "No external scanner was executed. "
                    "This integration generates deterministic CI evidence."
                ),
            },
        )

    def run(self, context: IntegrationContext) -> CIIntegrationResult:
        return self.execute(context)

    def describe(self) -> dict[str, str]:
        return {"name": self.name, "type": "ci", "mode": "synthetic"}
"""Default SecureForge integration definitions."""


