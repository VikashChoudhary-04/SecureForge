"""Security requirement models used by SecureForge."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RequirementCategory(str, Enum):
    """Security requirement categories."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    API = "api"
    INPUT = "input"
    SECRET = "secret"
    DEPENDENCY = "dependency"
    CONTAINER = "container"
    INFRASTRUCTURE = "infrastructure"
    TRANSPORT = "transport"
    REGRESSION = "regression"


class RequirementStatus(str, Enum):
    """Lifecycle status of a security requirement."""

    ACTIVE = "active"
    DISABLED = "disabled"
    DEPRECATED = "deprecated"


class SecurityRequirement(BaseModel):
    """A security requirement that SecureForge can evaluate."""

    model_config = ConfigDict(extra="allow")

    requirement_id: str
    title: str
    description: str

    category: RequirementCategory

    status: RequirementStatus = RequirementStatus.ACTIVE

    owasp: str | None = None
    cwe: list[str] = Field(default_factory=list)

    verification_methods: list[str] = Field(default_factory=list)

    mandatory: bool = False

    metadata: dict[str, Any] = Field(default_factory=dict)

    def is_active(self) -> bool:
        """Return whether the requirement is currently active."""
        return self.status == RequirementStatus.ACTIVE

    def is_mandatory(self) -> bool:
        """Return whether the requirement is mandatory."""
        return self.mandatory and self.is_active()


__all__ = [
    "RequirementCategory",
    "RequirementStatus",
    "SecurityRequirement",
]
