"""Tests for the SecureForge security requirement registry."""

import pytest

from secureforge.core.requirements import (
RequirementCategory,
RequirementStatus,
SecurityRequirement,
)
from secureforge.core.requirements.registry import RequirementRegistry

def build_requirement(
requirement_id: str = "SF-AUTHZ-001",
*,
mandatory: bool = False,
status: RequirementStatus = RequirementStatus.ACTIVE,
) -> SecurityRequirement:
"""Create a representative security requirement."""
return SecurityRequirement(
requirement_id=requirement_id,
title="Object-level authorization",
description=(
"Users must only access objects they are authorized to access."
),
category=RequirementCategory.AUTHORIZATION,
status=status,
owasp="API1:2023",
cwe=["CWE-639"],
verification_methods=[
"DAST",
"manual",
"regression",
],
mandatory=mandatory,
)

def test_registry_registers_requirement() -> None:
"""Verify a requirement can be registered."""
registry = RequirementRegistry()

```
requirement = build_requirement()

registry.register(requirement)

assert len(registry) == 1
assert registry.get("SF-AUTHZ-001") == requirement
```

def test_registry_accepts_initial_requirements() -> None:
"""Verify requirements can be supplied during initialization."""
first = build_requirement("SF-AUTHZ-001")
second = build_requirement("SF-AUTHZ-002")

```
registry = RequirementRegistry(
    [
        first,
        second,
    ]
)

assert len(registry) == 2
assert registry.contains("SF-AUTHZ-001")
assert registry.contains("SF-AUTHZ-002")
```

def test_registry_normalizes_requirement_id() -> None:
"""Verify requirement IDs are matched case-insensitively."""
registry = RequirementRegistry()

```
registry.register(
    build_requirement("sf-authz-001")
)

assert registry.contains("SF-AUTHZ-001")
assert registry.contains("sf-authz-001")
assert registry.get("Sf-AuThZ-001") is not None
```

def test_registry_rejects_duplicate_requirement() -> None:
"""Verify duplicate registration is rejected by default."""
registry = RequirementRegistry()

```
registry.register(
    build_requirement()
)

with pytest.raises(
    ValueError,
    match="is already registered",
):
    registry.register(
        build_requirement()
    )
```

def test_registry_allows_duplicate_with_replace() -> None:
"""Verify an existing requirement can be replaced explicitly."""
registry = RequirementRegistry()

```
original = build_requirement(
    "SF-AUTHZ-001"
)

replacement = build_requirement(
    "SF-AUTHZ-001"
)
replacement.title = "Updated authorization requirement"

registry.register(original)
registry.register(
    replacement,
    replace=True,
)

assert len(registry) == 1
assert registry.require(
    "SF-AUTHZ-001"
).title == "Updated authorization requirement"
```

def test_registry_rejects_empty_requirement_id() -> None:
"""Verify an empty requirement ID is rejected."""
registry = RequirementRegistry()

```
requirement = build_requirement("   ")

with pytest.raises(
    ValueError,
    match="ID cannot be empty",
):
    registry.register(requirement)
```

def test_registry_get_returns_none_for_missing_requirement() -> None:
"""Verify missing lookups return None."""
registry = RequirementRegistry()

```
assert registry.get("SF-AUTHZ-999") is None
```

def test_registry_require_raises_for_missing_requirement() -> None:
"""Verify required lookup raises a clear error."""
registry = RequirementRegistry()

```
with pytest.raises(
    KeyError,
    match="SF-AUTHZ-999",
):
    registry.require("SF-AUTHZ-999")
```

def test_registry_contains_works() -> None:
"""Verify membership checks work."""
registry = RequirementRegistry()

```
registry.register(
    build_requirement()
)

assert registry.contains("SF-AUTHZ-001")
assert "SF-AUTHZ-001" in registry
assert not registry.contains("SF-AUTHZ-999")
```

def test_registry_remove_returns_requirement() -> None:
"""Verify requirements can be removed."""
registry = RequirementRegistry()

```
requirement = build_requirement()

registry.register(requirement)

removed = registry.remove(
    "SF-AUTHZ-001"
)

assert removed == requirement
assert len(registry) == 0
assert not registry.contains("SF-AUTHZ-001")
```

def test_registry_remove_missing_requirement_raises() -> None:
"""Verify removing a missing requirement raises an error."""
registry = RequirementRegistry()

```
with pytest.raises(
    KeyError,
    match="SF-AUTHZ-999",
):
    registry.remove("SF-AUTHZ-999")
```

def test_registry_all_returns_registered_requirements() -> None:
"""Verify all requirements are returned."""
first = build_requirement("SF-AUTHZ-001")
second = build_requirement("SF-AUTHZ-002")

```
registry = RequirementRegistry(
    [
        first,
        second,
    ]
)

requirements = registry.all()

assert len(requirements) == 2
assert requirements[0] == first
assert requirements[1] == second
```

def test_registry_active_returns_only_active_requirements() -> None:
"""Verify disabled and deprecated requirements are excluded."""
active = build_requirement(
"SF-AUTHZ-001",
status=RequirementStatus.ACTIVE,
)

```
disabled = build_requirement(
    "SF-AUTHZ-002",
    status=RequirementStatus.DISABLED,
)

deprecated = build_requirement(
    "SF-AUTHZ-003",
    status=RequirementStatus.DEPRECATED,
)

registry = RequirementRegistry(
    [
        active,
        disabled,
        deprecated,
    ]
)

active_requirements = registry.active()

assert active_requirements == [active]
```

def test_registry_mandatory_returns_only_active_mandatory_requirements() -> None:
"""Verify mandatory filtering respects lifecycle status."""
mandatory_active = build_requirement(
"SF-AUTHZ-001",
mandatory=True,
status=RequirementStatus.ACTIVE,
)

```
optional_active = build_requirement(
    "SF-AUTHZ-002",
    mandatory=False,
    status=RequirementStatus.ACTIVE,
)

mandatory_disabled = build_requirement(
    "SF-AUTHZ-003",
    mandatory=True,
    status=RequirementStatus.DISABLED,
)

registry = RequirementRegistry(
    [
        mandatory_active,
        optional_active,
        mandatory_disabled,
    ]
)

mandatory_requirements = registry.mandatory()

assert mandatory_requirements == [
    mandatory_active
]
```

def test_registry_register_many_returns_count() -> None:
"""Verify bulk registration returns the number registered."""
requirements = [
build_requirement("SF-AUTHZ-001"),
build_requirement("SF-AUTHZ-002"),
build_requirement("SF-AUTHZ-003"),
]

```
registry = RequirementRegistry()

count = registry.register_many(
    requirements
)

assert count == 3
assert len(registry) == 3
```

def test_registry_register_many_rejects_duplicate() -> None:
"""Verify bulk registration uses duplicate protection."""
registry = RequirementRegistry()

```
registry.register(
    build_requirement("SF-AUTHZ-001")
)

with pytest.raises(
    ValueError,
    match="is already registered",
):
    registry.register_many(
        [
            build_requirement("SF-AUTHZ-002"),
            build_requirement("SF-AUTHZ-001"),
        ]
    )
```

def test_registry_clear_removes_all_requirements() -> None:
"""Verify the registry can be cleared."""
registry = RequirementRegistry(
[
build_requirement("SF-AUTHZ-001"),
build_requirement("SF-AUTHZ-002"),
]
)

```
registry.clear()

assert len(registry) == 0
assert registry.all() == []
```

def test_registry_len_tracks_requirements() -> None:
"""Verify len() reflects the number of requirements."""
registry = RequirementRegistry()

```
assert len(registry) == 0

registry.register(
    build_requirement("SF-AUTHZ-001")
)

assert len(registry) == 1

registry.register(
    build_requirement("SF-AUTHZ-002")
)

assert len(registry) == 2
```
