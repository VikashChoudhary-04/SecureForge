"""Tests for the SecureForge integration registry."""

import pytest

from secureforge.core.config import ScanConfiguration
from secureforge.core.normalization import (
NormalizationResult,
RawEvidence,
)
from secureforge.integrations.base import (
SecurityIntegration,
)
from secureforge.integrations.registry import (
IntegrationRegistry,
)

class FakeIntegration(SecurityIntegration):
"""Controlled integration implementation for tests."""

```
integration_name = "sast"
display_name = "Fake SAST"

def build_command(
    self,
    configuration: ScanConfiguration,
) -> list[str]:
    """Return a controlled command."""
    return [
        "fake-sast",
        "--scan",
    ]

def normalize(
    self,
    evidence: RawEvidence,
) -> NormalizationResult:
    """Return a controlled normalization result."""
    return NormalizationResult(
        source=self.integration_name,
        success=True,
    )
```

class AlternateIntegration(SecurityIntegration):
"""Second controlled integration implementation."""

```
integration_name = "nmap"
display_name = "Fake Nmap"

def build_command(
    self,
    configuration: ScanConfiguration,
) -> list[str]:
    """Return a controlled command."""
    return [
        "nmap",
        "-sV",
    ]

def normalize(
    self,
    evidence: RawEvidence,
) -> NormalizationResult:
    """Return a controlled normalization result."""
    return NormalizationResult(
        source=self.integration_name,
        success=True,
    )
```

class ReplacementIntegration(SecurityIntegration):
"""Replacement implementation for registry tests."""

```
integration_name = "sast"
display_name = "Replacement SAST"

def build_command(
    self,
    configuration: ScanConfiguration,
) -> list[str]:
    """Return a replacement command."""
    return [
        "replacement-sast",
    ]

def normalize(
    self,
    evidence: RawEvidence,
) -> NormalizationResult:
    """Return a controlled normalization result."""
    return NormalizationResult(
        source=self.integration_name,
        success=True,
    )
```

def test_empty_registry_has_no_integrations() -> None:
"""Verify a new registry starts empty."""
registry = IntegrationRegistry()

```
assert len(registry) == 0
assert registry.all() == []
assert registry.names() == []
```

def test_register_adds_integration() -> None:
"""Verify an integration can be registered."""
registry = IntegrationRegistry()

```
integration = FakeIntegration()

registry.register(
    integration
)

assert len(registry) == 1
assert registry.contains("sast")
assert "sast" in registry
```

def test_register_normalizes_name() -> None:
"""Verify integration names are normalized."""
class MixedCaseIntegration(FakeIntegration):
integration_name = "  SAST  "

```
registry = IntegrationRegistry()

integration = MixedCaseIntegration()

registry.register(
    integration
)

assert registry.contains("sast")
assert registry.get(" SAST ") is integration
assert registry.names() == ["sast"]
```

def test_register_duplicate_raises() -> None:
"""Verify duplicate registration is rejected by default."""
registry = IntegrationRegistry()

```
registry.register(
    FakeIntegration()
)

with pytest.raises(
    ValueError,
    match="already registered",
):
    registry.register(
        FakeIntegration()
    )
```

def test_register_can_replace_existing_integration() -> None:
"""Verify explicit replacement works."""
registry = IntegrationRegistry()

```
original = FakeIntegration()
replacement = ReplacementIntegration()

registry.register(
    original
)

registry.register(
    replacement,
    replace=True,
)

assert registry.get("sast") is replacement
assert registry.get("sast").display_name == (
    "Replacement SAST"
)
```

def test_register_many_adds_all_integrations() -> None:
"""Verify multiple integrations can be registered."""
registry = IntegrationRegistry()

```
count = registry.register_many(
    [
        FakeIntegration(),
        AlternateIntegration(),
    ]
)

assert count == 2
assert len(registry) == 2
assert registry.contains("sast")
assert registry.contains("nmap")
```

def test_register_many_returns_number_of_inputs() -> None:
"""Verify register_many reports the number of registered inputs."""
registry = IntegrationRegistry()

```
integrations = [
    FakeIntegration(),
    AlternateIntegration(),
]

assert (
    registry.register_many(
        integrations
    )
    == 2
)
```

def test_constructor_accepts_integrations() -> None:
"""Verify integrations can be provided during construction."""
registry = IntegrationRegistry(
[
FakeIntegration(),
AlternateIntegration(),
]
)

```
assert len(registry) == 2
assert registry.contains("sast")
assert registry.contains("nmap")
```

def test_get_returns_registered_integration() -> None:
"""Verify lookup returns the original object."""
registry = IntegrationRegistry()

```
integration = FakeIntegration()

registry.register(
    integration
)

assert registry.get("sast") is integration
```

def test_get_returns_none_for_unknown_integration() -> None:
"""Verify unknown integrations return None."""
registry = IntegrationRegistry()

```
assert registry.get("unknown") is None
```

def test_require_returns_registered_integration() -> None:
"""Verify require returns a registered integration."""
registry = IntegrationRegistry()

```
integration = FakeIntegration()

registry.register(
    integration
)

assert registry.require("sast") is integration
```

def test_require_raises_for_unknown_integration() -> None:
"""Verify require raises a clear lookup error."""
registry = IntegrationRegistry()

```
with pytest.raises(
    KeyError,
    match="not registered",
):
    registry.require("unknown")
```

def test_contains_is_case_insensitive() -> None:
"""Verify membership checks normalize names."""
registry = IntegrationRegistry()

```
registry.register(
    FakeIntegration()
)

assert registry.contains("SAST")
assert registry.contains(" sast ")
assert "SAST" in registry
```

def test_remove_returns_removed_integration() -> None:
"""Verify an integration can be removed."""
registry = IntegrationRegistry()

```
integration = FakeIntegration()

registry.register(
    integration
)

removed = registry.remove(
    "sast"
)

assert removed is integration
assert len(registry) == 0
assert not registry.contains("sast")
```

def test_remove_unknown_integration_raises() -> None:
"""Verify removing an unknown integration raises."""
registry = IntegrationRegistry()

```
with pytest.raises(
    KeyError,
    match="not registered",
):
    registry.remove("unknown")
```

def test_all_returns_registered_integrations() -> None:
"""Verify all returns registered integration objects."""
registry = IntegrationRegistry()

```
sast = FakeIntegration()
nmap = AlternateIntegration()

registry.register(
    sast
)
registry.register(
    nmap
)

integrations = registry.all()

assert integrations == [
    sast,
    nmap,
]
```

def test_names_returns_registered_names() -> None:
"""Verify names returns canonical integration names."""
registry = IntegrationRegistry()

```
registry.register(
    FakeIntegration()
)
registry.register(
    AlternateIntegration()
)

assert registry.names() == [
    "sast",
    "nmap",
]
```

def test_clear_removes_all_integrations() -> None:
"""Verify clear empties the registry."""
registry = IntegrationRegistry(
[
FakeIntegration(),
AlternateIntegration(),
]
)

```
registry.clear()

assert len(registry) == 0
assert registry.all() == []
assert registry.names() == []
```

def test_empty_integration_name_is_rejected() -> None:
"""Verify integrations must define a canonical name."""
class EmptyNameIntegration(FakeIntegration):
integration_name = "   "

```
registry = IntegrationRegistry()

with pytest.raises(
    ValueError,
    match="Integration name cannot be empty",
):
    registry.register(
        EmptyNameIntegration()
    )
```
