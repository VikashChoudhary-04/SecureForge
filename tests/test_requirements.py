"""Tests for SecureForge security requirements."""

from secureforge.core.requirements import (
RequirementCategory,
RequirementStatus,
SecurityRequirement,
)

def build_requirement(
*,
mandatory: bool = False,
status: RequirementStatus = RequirementStatus.ACTIVE,
) -> SecurityRequirement:
"""Create a representative security requirement."""
return SecurityRequirement(
requirement_id="SF-AUTHZ-001",
title="Object-level authorization",
description=(
"Users must only access objects they are authorized to access."
),
category=RequirementCategory.AUTHORIZATION,
status=status,
owasp="API1",
cwe=["CWE-639"],
verification_methods=[
"dynamic",
"manual",
"regression",
],
mandatory=mandatory,
)

def test_requirement_is_created_correctly() -> None:
"""Verify the requirement model stores its core properties."""
requirement = build_requirement()

```
assert requirement.requirement_id == "SF-AUTHZ-001"
assert requirement.category == RequirementCategory.AUTHORIZATION
assert requirement.status == RequirementStatus.ACTIVE
assert requirement.mandatory is False
```

def test_active_requirement_is_active() -> None:
"""Verify an active requirement reports active state."""
requirement = build_requirement()

```
assert requirement.is_active() is True
```

def test_disabled_requirement_is_not_active() -> None:
"""Verify disabled requirements are not active."""
requirement = build_requirement(
status=RequirementStatus.DISABLED,
)

```
assert requirement.is_active() is False
```

def test_deprecated_requirement_is_not_active() -> None:
"""Verify deprecated requirements are not active."""
requirement = build_requirement(
status=RequirementStatus.DEPRECATED,
)

```
assert requirement.is_active() is False
```

def test_non_mandatory_requirement_is_not_mandatory() -> None:
"""Verify optional active requirements are not mandatory."""
requirement = build_requirement(mandatory=False)

```
assert requirement.is_mandatory() is False
```

def test_mandatory_active_requirement_is_mandatory() -> None:
"""Verify active mandatory requirements are recognized."""
requirement = build_requirement(mandatory=True)

```
assert requirement.is_active() is True
assert requirement.is_mandatory() is True
```

def test_mandatory_disabled_requirement_is_not_mandatory() -> None:
"""Verify disabled mandatory requirements cannot be mandatory."""
requirement = build_requirement(
mandatory=True,
status=RequirementStatus.DISABLED,
)

```
assert requirement.is_active() is False
assert requirement.is_mandatory() is False
```
