"""Registry for SecureForge security-tool integrations."""

from __future__ import annotations

from collections.abc import Iterable

from .base import SecurityIntegration

class IntegrationRegistry:
"""Register and retrieve SecureForge security integrations."""

    def __init__(
        self,
        integrations: Iterable[SecurityIntegration] | None = None,
    ) -> None:
        self._integrations: dict[str, SecurityIntegration] = {}
    
        if integrations:
            self.register_many(
                integrations
            )
    
    def register(
        self,
        integration: SecurityIntegration,
        *,
        replace: bool = False,
    ) -> None:
        """Register a security integration."""
        integration_name = self._normalize_name(
            integration.name
        )
    
        if not integration_name:
            raise ValueError(
                "Integration name cannot be empty."
            )
    
        if (
            integration_name in self._integrations
            and not replace
        ):
            raise ValueError(
                f"Integration '{integration_name}' "
                "is already registered."
            )
    
        self._integrations[
            integration_name
        ] = integration
    
    def register_many(
        self,
        integrations: Iterable[SecurityIntegration],
        *,
        replace: bool = False,
    ) -> int:
        """Register multiple security integrations."""
        integrations_list = list(
            integrations
        )
    
        for integration in integrations_list:
            self.register(
                integration,
                replace=replace,
            )
    
        return len(
            integrations_list
        )

def get(
    self,
    name: str,
) -> SecurityIntegration | None:
    """Return an integration by canonical name."""
    integration_name = self._normalize_name(
        name
    )

    return self._integrations.get(
        integration_name
    )

def require(
    self,
    name: str,
) -> SecurityIntegration:
    """Return an integration or raise a clear lookup error."""
    integration = self.get(
        name
    )

    if integration is None:
        integration_name = self._normalize_name(
            name
        )

        raise KeyError(
            f"Security integration "
            f"'{integration_name}' is not registered."
        )

    return integration

def contains(
    self,
    name: str,
) -> bool:
    """Return whether an integration is registered."""
    return self.get(
        name
    ) is not None

def remove(
    self,
    name: str,
) -> SecurityIntegration:
    """Remove and return an integration."""
    integration_name = self._normalize_name(
        name
    )

    try:
        return self._integrations.pop(
            integration_name
        )
    except KeyError as exc:
        raise KeyError(
            f"Security integration "
            f"'{integration_name}' is not registered."
        ) from exc

def all(self) -> list[SecurityIntegration]:
    """Return all registered integrations."""
    return list(
        self._integrations.values()
    )

def names(self) -> list[str]:
    """Return registered integration names."""
    return list(
        self._integrations.keys()
    )

def clear(self) -> None:
    """Remove all registered integrations."""
    self._integrations.clear()

def __len__(self) -> int:
    """Return the number of registered integrations."""
    return len(
        self._integrations
    )

def __contains__(
    self,
    name: str,
) -> bool:
    """Support membership checks using integration names."""
    return self.contains(
        name
    )

@staticmethod
def _normalize_name(
    name: str,
) -> str:
    """Normalize an integration name."""
    return name.strip().lower()
