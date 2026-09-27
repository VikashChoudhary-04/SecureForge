"""Registry for SecureForge normalization adapters."""

from **future** import annotations

from .base import NormalizationAdapter

class NormalizationRegistry:
"""Register and retrieve normalization adapters by source name."""

```
def __init__(self) -> None:
    self._adapters: dict[
        str,
        NormalizationAdapter,
    ] = {}

def register(
    self,
    adapter: NormalizationAdapter,
    *,
    replace: bool = False,
) -> None:
    """Register a normalization adapter.

    Args:
        adapter: Adapter instance to register.
        replace: Replace an existing adapter with the same source.

    Raises:
        ValueError: If the adapter source is invalid or already exists.
    """
    source_name = self._normalize_source(
        adapter.source_name
    )

    if not source_name:
        raise ValueError(
            "Normalization adapter source name cannot be empty."
        )

    if (
        source_name in self._adapters
        and not replace
    ):
        raise ValueError(
            f"Normalization adapter '{source_name}' "
            "is already registered."
        )

    self._adapters[source_name] = adapter

def register_many(
    self,
    adapters: list[NormalizationAdapter],
    *,
    replace: bool = False,
) -> int:
    """Register multiple adapters.

    Returns:
        Number of adapters registered.
    """
    for adapter in adapters:
        self.register(
            adapter,
            replace=replace,
        )

    return len(adapters)

def get(
    self,
    source: str,
) -> NormalizationAdapter | None:
    """Return the adapter registered for a source."""
    source_name = self._normalize_source(source)

    return self._adapters.get(source_name)

def require(
    self,
    source: str,
) -> NormalizationAdapter:
    """Return a source adapter or raise a clear error."""
    adapter = self.get(source)

    if adapter is None:
        source_name = self._normalize_source(source)

        raise KeyError(
            f"No normalization adapter is registered "
            f"for source '{source_name}'."
        )

    return adapter

def contains(
    self,
    source: str,
) -> bool:
    """Return whether an adapter is registered."""
    return self.get(source) is not None

def remove(
    self,
    source: str,
) -> NormalizationAdapter:
    """Remove and return a registered adapter."""
    source_name = self._normalize_source(source)

    try:
        return self._adapters.pop(source_name)
    except KeyError as exc:
        raise KeyError(
            f"No normalization adapter is registered "
            f"for source '{source_name}'."
        ) from exc

def all(self) -> list[NormalizationAdapter]:
    """Return all registered adapters."""
    return list(self._adapters.values())

def sources(self) -> list[str]:
    """Return registered source names."""
    return list(self._adapters.keys())

def clear(self) -> None:
    """Remove all registered adapters."""
    self._adapters.clear()

def __len__(self) -> int:
    """Return the number of registered adapters."""
    return len(self._adapters)

@staticmethod
def _normalize_source(source: str) -> str:
    """Normalize a source identifier."""
    return source.strip().lower()
```
