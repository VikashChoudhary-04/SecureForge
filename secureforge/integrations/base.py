"""Base interfaces for SecureForge security-tool integrations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from secureforge.core.config import ScanConfiguration
from secureforge.core.normalization import NormalizationResult, RawEvidence
from secureforge.core.scan import ToolExecutionResult

class IntegrationError(Exception):
    """Base exception raised by SecureForge integrations."""

class IntegrationConfigurationError(IntegrationError):
    """Raised when an integration is incorrectly configured."""

class IntegrationParseError(IntegrationError):
    """Raised when an integration cannot parse tool output."""

class SecurityIntegration(ABC):
    """Base contract implemented by SecureForge security integrations."""

    integration_name: str = "unknown"
    display_name: str = "Unknown Security Integration"
    
    def __init__(
        self,
        *,
        version: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.version = version
        self.metadata = dict(metadata or {})
    
    @abstractmethod
    def build_command(
        self,
        configuration: ScanConfiguration,
    ) -> list[str]:
        """Build the command used to execute the integration."""
        raise NotImplementedError
    
    @abstractmethod
    def normalize(
        self,
        evidence: RawEvidence,
    ) -> NormalizationResult:
        """Convert integration output into SecureForge findings."""
        raise NotImplementedError
    
    def validate_configuration(
        self,
        configuration: ScanConfiguration,
    ) -> None:
        """Validate configuration before integration execution."""
        if not configuration.application.strip():
            raise IntegrationConfigurationError(
                "Application name cannot be empty."
            )
    
        if not configuration.target.name.strip():
            raise IntegrationConfigurationError(
                "Target name cannot be empty."
            )
    
    def supports_target(
        self,
        configuration: ScanConfiguration,
    ) -> bool:
        """Return whether the integration supports the configured target."""
        return True
    
    def create_evidence(
        self,
        result: ToolExecutionResult,
        *,
        target: str | None = None,
    ) -> RawEvidence:
        """Convert a tool execution result into raw evidence."""
        metadata = dict(
            self.metadata
        )
    
        metadata.setdefault(
            "integration",
            self.integration_name,
        )
    
        if self.version is not None:
            metadata.setdefault(
                "source_version",
                self.version,
            )
    
        raw_data = {
            "tool_name": result.tool_name,
            "integration": result.integration,
            "status": result.status.value,
            "command": result.command,
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "duration_seconds": result.duration_seconds,
            "error": result.error,
        }
    
        return RawEvidence(
            source=self.integration_name,
            source_version=self.version,
            source_reference=result.evidence_path,
            target=target,
            collected_at=(
                result.completed_at
                or result.started_at
            ),
            raw_data=raw_data,
            metadata=metadata,
        )

def integration_metadata(self) -> dict[str, Any]:
    """Return metadata describing this integration."""
    return {
        "integration": self.integration_name,
        "display_name": self.display_name,
        "version": self.version,
        **self.metadata,
    }

@property
def name(self) -> str:
    """Return the canonical integration name."""
    return self.integration_name
