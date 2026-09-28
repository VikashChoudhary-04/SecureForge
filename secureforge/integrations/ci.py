"""Deterministic CI integration for SecureForge."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from secureforge.core.findings.models import (
    Confidence,
    Evidence,
    Finding,
    Severity,
)
from secureforge.integrations.base import (
    BaseIntegration,
    IntegrationContext,
    IntegrationExecutionResult,
)


class CIIntegration(BaseIntegration):
    """Produce deterministic synthetic evidence for CI verification.

    This integration exists for SecureForge's own pipeline testing.
    It does not represent execution of a real external security scanner.
    """

    name = "ci"
    version = "1.0"

    def supports(self, context: IntegrationContext) -> bool:
        """Return whether the CI integration can run."""
        return context.environment.lower() in {
            "ci",
            "test",
        }

    def execute(
        self,
        context: IntegrationContext,
    ) -> IntegrationExecutionResult:
        """Return deterministic CI security evidence."""
        if not self.supports(context):
            return IntegrationExecutionResult(
                integration=self.name,
                success=False,
                findings=[],
                error=(
                    "CI integration is only available in "
                    "ci or test environments."
                ),
            )

        finding = self._build_finding(context)

        return IntegrationExecutionResult(
            integration=self.name,
            success=True,
            findings=[finding],
            metadata={
                "mode": "synthetic",
                "source": "secureforge-ci",
                "generated_at": datetime.now(
                    timezone.utc
                ).isoformat(),
                "note": (
                    "Synthetic evidence used for deterministic "
                    "SecureForge pipeline testing. "
                    "No external scanner was executed."
                ),
            },
        )

    def describe(self) -> dict[str, Any]:
        """Return integration metadata."""
        return {
            "name": self.name,
            "version": self.version,
            "type": "ci",
            "mode": "synthetic",
            "description": (
                "Deterministic synthetic security evidence "
                "for SecureForge CI and integration testing."
            ),
        }

    @staticmethod
    def _build_finding(
        context: IntegrationContext,
    ) -> Finding:
        """Build a deterministic informational finding."""
        return Finding(
            finding_id="CI-001",
            title="SecureForge CI Verification Evidence",
            source="ci",
            asset=context.target or context.application,
            application=context.application,
            endpoint=None,
            parameter=None,
            cwe=None,
            owasp_mapping=None,
            security_requirement="SF-REG-001",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            evidence=[
                Evidence(
                    source="ci",
                    description=(
                        "SecureForge generated deterministic "
                        "synthetic evidence to verify the "
                        "security pipeline."
                    ),
                    request=None,
                    response=None,
                    command=None,
                    output=(
                        "Synthetic CI verification evidence"
                    ),
                    expected=(
                        "SecureForge pipeline processes "
                        "CI evidence successfully."
                    ),
                    observed=(
                        "Synthetic evidence generated successfully."
                    ),
                )
            ],
            description=(
                "Synthetic evidence used to verify SecureForge "
                "normalization, risk, policy, reporting, and "
                "release-gate behavior in CI."
            ),
            impact=(
                "No application vulnerability is asserted. "
                "This is a pipeline verification finding."
            ),
            remediation=(
                "No remediation required. This finding exists "
                "only for deterministic CI verification."
            ),
        )
