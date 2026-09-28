```python id="4t8m2q"
"""Factory functions for SecureForge validation services."""

from __future__ import annotations

from .api import APIValidator
from .command import CommandValidator
from .engine import ValidationEngine
from .http import HTTPValidator
from .manual import ManualValidator
from .registry import ValidatorRegistry
from .script import ScriptValidator
from .securecommerce import SecureCommerceValidator


def build_validation_registry(
    *,
    command_allowlist: set[str] | None = None,
    command_timeout: int = 30,
) -> ValidatorRegistry:
    """Build the default SecureForge validation registry."""
    validators = [
        SecureCommerceValidator(),
        HTTPValidator(),
        APIValidator(),
        CommandValidator(
            allowlist=command_allowlist,
            timeout=command_timeout,
        ),
        ScriptValidator(
            timeout=command_timeout,
        ),
        ManualValidator(),
    ]

    return ValidatorRegistry(
        validators=validators
    )


def build_validation_engine(
    *,
    command_allowlist: set[str] | None = None,
    command_timeout: int = 30,
) -> ValidationEngine:
    """Build a validation engine with default validators."""
    registry = build_validation_registry(
        command_allowlist=command_allowlist,
        command_timeout=command_timeout,
    )

    return ValidationEngine(
        registry=registry
    )


__all__ = [
    "build_validation_engine",
    "build_validation_registry",
]
```
