```python id="d8m4q2"
"""Validator registry for SecureForge."""

from __future__ import annotations

from .base import (
    BaseValidator,
)
from .models import (
    ValidationRequest,
)


class ValidatorRegistryError(Exception):
    """Raised when validator registration or lookup fails."""


class ValidatorRegistry:
    """Store and resolve security validators."""

    def __init__(
        self,
        validators: list[BaseValidator] | None = None,
    ) -> None:
        self._validators: dict[str, BaseValidator] = {}

        if validators is not None:
            for validator in validators:
                self.register(
                    validator
                )

    def register(
        self,
        validator: BaseValidator,
    ) -> None:
        """Register a validator by its unique name."""
        name = validator.name.strip()

        if not name:
            raise ValidatorRegistryError(
                "Validator name must not be empty."
            )

        if name in self._validators:
            raise ValidatorRegistryError(
                f"Validator already registered: {name}"
            )

        self._validators[name] = validator

    def unregister(
        self,
        name: str,
    ) -> BaseValidator:
        """Remove and return a registered validator."""
        if name not in self._validators:
            raise ValidatorRegistryError(
                f"Validator not registered: {name}"
            )

        return self._validators.pop(
            name
        )

    def get(
        self,
        name: str,
    ) -> BaseValidator:
        """Return a validator by name."""
        validator = self._validators.get(
            name
        )

        if validator is None:
            raise ValidatorRegistryError(
                f"Validator not registered: {name}"
            )

        return validator

    def find(
        self,
        request: ValidationRequest,
    ) -> BaseValidator:
        """Find the first validator supporting a request."""
        for validator in self._validators.values():
            if validator.supports(request):
                return validator

        raise ValidatorRegistryError(
            "No validator supports the requested validation."
        )

    def list(
        self,
    ) -> list[BaseValidator]:
        """Return registered validators."""
        return list(
            self._validators.values()
        )

    def names(
        self,
    ) -> list[str]:
        """Return registered validator names."""
        return list(
            self._validators.keys()
        )

    def __len__(
        self,
    ) -> int:
        """Return the number of registered validators."""
        return len(
            self._validators
        )
```
