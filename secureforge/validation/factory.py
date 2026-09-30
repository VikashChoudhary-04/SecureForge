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
    command_timeout: float = 30.0,
    http_timeout: float = 10.0,
    script_timeout: float = 10.0,
    api_timeout: float = 10.0,
    include_securecommerce: bool = False,
) -> ValidatorRegistry:
    """Build the default SecureForge validation registry."""
    validators = []

    if include_securecommerce:
        validators.append(
            SecureCommerceValidator()
        )

    validators.extend(
        [
            HTTPValidator(
                timeout=http_timeout,
            ),
            APIValidator(
                timeout=api_timeout,
            ),
            CommandValidator(
                allowlist=command_allowlist,
                timeout=command_timeout,
            ),
            ScriptValidator(
                timeout=script_timeout,
            ),
            ManualValidator(),
        ]
    )

    return ValidatorRegistry(
        validators=validators
    )


def build_validation_engine(
    *,
    command_allowlist: set[str] | None = None,
    command_timeout: float = 30.0,
    http_timeout: float = 10.0,
    script_timeout: float = 10.0,
    api_timeout: float = 10.0,
    include_securecommerce: bool = False,
) -> ValidationEngine:
    """Build a validation engine with configured validators."""
    registry = build_validation_registry(
        command_allowlist=command_allowlist,
        command_timeout=command_timeout,
        http_timeout=http_timeout,
        script_timeout=script_timeout,
        api_timeout=api_timeout,
        include_securecommerce=include_securecommerce,
    )

    return ValidationEngine(
        registry=registry
    )


__all__ = [
    "build_validation_engine",
    "build_validation_registry",
]
