```python id="816x4m"
"""Factory helpers for SecureForge validation."""

from __future__ import annotations

from .api import APIValidator
from .command import CommandValidator
from .engine import ValidationEngine
from .http import HTTPValidator
from .manual import ManualValidator
from .registry import ValidatorRegistry
from .script import ScriptValidator


def build_validation_registry(
    *,
    command_allowlist: set[str] | None = None,
    command_timeout: float = 10.0,
    http_timeout: float = 10.0,
    script_timeout: float = 10.0,
    api_timeout: float = 10.0,
) -> ValidatorRegistry:
    """Build the default SecureForge validation registry."""
    registry = ValidatorRegistry()

    registry.register(
        HTTPValidator(
            timeout=http_timeout,
        )
    )
    registry.register(
        APIValidator(
            timeout=api_timeout,
        )
    )
    registry.register(
        CommandValidator(
            allowed_commands=command_allowlist,
            timeout=command_timeout,
        )
    )
    registry.register(
        ScriptValidator(
            timeout=script_timeout,
        )
    )
    registry.register(ManualValidator())

    return registry


def build_validation_engine(
    *,
    command_allowlist: set[str] | None = None,
    command_timeout: float = 10.0,
    http_timeout: float = 10.0,
    script_timeout: float = 10.0,
    api_timeout: float = 10.0,
) -> ValidationEngine:
    """Build a validation engine with the default validators."""
    registry = build_validation_registry(
        command_allowlist=command_allowlist,
        command_timeout=command_timeout,
        http_timeout=http_timeout,
        script_timeout=script_timeout,
        api_timeout=api_timeout,
    )

    return ValidationEngine(registry)
```
