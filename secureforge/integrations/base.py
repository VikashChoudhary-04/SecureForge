"""Base abstractions for SecureForge security integrations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class IntegrationContext:
    """Execution context supplied to a security integration."""

    target: str | None = None
    application: str = "unknown"
    version: str = "unknown"
    environment: str = "lab"
    workspace: str | None = None
    metadata: dict[str, Any] = field(
        default_factory=dict
    )


@dataclass
class IntegrationResult:
    """Standard result returned by a security integration."""

    integration: str
    success: bool = True
    findings: list[dict[str, Any]] = field(
        default_factory=list
    )
    evidence: list[dict[str, Any]] = field(
        default_factory=list
    )
    warnings: list[str] = field(
        default_factory=list
    )
    errors: list[str] = field(
        default_factory=list
    )
    raw_output: Any = None
    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    @property
    def failed(self) -> bool:
        """Return whether the integration failed."""
        return not self.success


class SecurityIntegration(ABC):
    """Base interface implemented by SecureForge integrations."""

    name: str = "unknown"

    @abstractmethod
    def run(
        self,
        context: IntegrationContext,
    ) -> IntegrationResult:
        """Execute the integration against the supplied context."""
        raise NotImplementedError
