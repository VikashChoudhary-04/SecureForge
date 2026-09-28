"""Base interfaces for SecureForge security validation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from .models import (
    ValidationRequest,
    ValidationResult,
)


class ValidationError(Exception):
    """Raised when a security validation cannot be completed."""


class BaseValidator(ABC):
    """Abstract interface for finding validators."""

    name: str = "base"

    @abstractmethod
    def supports(
        self,
        request: ValidationRequest,
    ) -> bool:
        """Return whether this validator supports the request."""
        raise NotImplementedError

    @abstractmethod
    def validate(
        self,
        request: ValidationRequest,
    ) -> ValidationResult:
        """Validate a security finding."""
        raise NotImplementedError

    def describe(self) -> dict[str, Any]:
        """Return metadata describing the validator."""
        return {
            "name": self.name,
        }


__all__ = [
    "BaseValidator",
    "ValidationError",
]
