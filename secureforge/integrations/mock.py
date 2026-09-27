"""Deterministic mock security integration for SecureForge testing."""

from **future** import annotations

from typing import Any

from secureforge.core.config import ScanConfiguration
from secureforge.core.normalization import (
NormalizationResult,
RawEvidence,
)
from secureforge.core.scan import (
ToolExecutionResult,
ToolExecutionStatus,
)

from .base import SecurityIntegration

class MockSecurityIntegration(SecurityIntegration):
"""Controlled integration that produces deterministic findings."""

```
integration_name = "mock"
display_name = "Mock Security Scanner"

def __init__(
    self,
    *,
    findings: list[dict[str, Any]] | None = None,
    version: str = "1.0.0",
    metadata: dict[str, Any] | None = None,
) -> None:
    super().__init__(
        version=version,
        metadata=metadata,
    )

    self.findings = list(
        findings or []
    )

def build_command(
    self,
    configuration: ScanConfiguration,
) -> list[str]:
    """Return a deterministic mock command."""
    self.validate_configuration(
        configuration
    )

    return [
        "secureforge-mock",
        "--application",
        configuration.application,
        "--target",
        configuration.target.name,
    ]

def normalize(
    self,
    evidence: RawEvidence,
) -> NormalizationResult:
    """Convert mock evidence into normalized findings."""
    if evidence.source != self.integration_name:
        raise ValueError(
            f"Expected evidence source "
            f"'{self.integration_name}', "
            f"received '{evidence.source}'."
        )

    return NormalizationResult(
        source=self.integration_name,
        findings=list(
            self.findings
        ),
        evidence=[
            evidence
        ],
        success=True,
    )

def execute(
    self,
    configuration: ScanConfiguration,
) -> ToolExecutionResult:
    """Produce a successful deterministic tool result."""
    command = self.build_command(
        configuration
    )

    return ToolExecutionResult(
        tool_name=self.integration_name,
        integration=self.integration_name,
        status=ToolExecutionStatus.SUCCESS,
        command=command,
        exit_code=0,
        stdout=(
            "Mock security scan completed successfully."
        ),
        stderr="",
        duration_seconds=0.0,
        metadata=self.integration_metadata(),
    )

def add_finding(
    self,
    finding: dict[str, Any],
) -> None:
    """Add a normalized finding to the mock scanner."""
    if not isinstance(
        finding,
        dict,
    ):
        raise TypeError(
            "Mock finding must be a dictionary."
        )

    self.findings.append(
        dict(finding)
    )

def clear_findings(self) -> None:
    """Remove all configured mock findings."""
    self.findings.clear()

def create_evidence_from_execution(
    self,
    result: ToolExecutionResult,
    configuration: ScanConfiguration,
) -> RawEvidence:
    """Create raw evidence from a mock execution result."""
    return self.create_evidence(
        result,
        target=(
            configuration.target.base_url
            or configuration.target.api_base_url
            or configuration.target.name
        ),
    )
```
