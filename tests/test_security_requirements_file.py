"""Tests for the repository security requirements definition."""

from pathlib import Path

from secureforge.core.requirements import (
RequirementCategory,
RequirementLoader,
RequirementStatus,
)

REPOSITORY_ROOT = Path(**file**).resolve().parents[1]
REQUIREMENTS_FILE = (
REPOSITORY_ROOT
/ "requirements"
/ "security-requirements.yaml"
)

EXPECTED_REQUIREMENTS = {
"SF-AUTH-001",
"SF-AUTH-002",
"SF-AUTHZ-001",
"SF-AUTHZ-002",
"SF-API-001",
"SF-API-002",
"SF-INPUT-001",
"SF-SECRET-001",
"SF-DEP-001",
"SF-CONTAINER-001",
"SF-IAC-001",
"SF-TRANSPORT-001",
"SF-REG-001",
}

def test_repository_requirements_file_exists() -> None:
"""Verify the repository requirements file exists."""
assert REQUIREMENTS_FILE.exists()
assert REQUIREMENTS_FILE.is_file()

def test_repository_requirements_load_successfully() -> None:
"""Verify the repository requirements YAML is valid."""
loader = RequirementLoader()

```
requirements = loader.load_file(
    REQUIREMENTS_FILE
)

assert requirements
assert len(requirements) == len(
    EXPECTED_REQUIREMENTS
)
```

def test_repository_contains_expected_requirements() -> None:
"""Verify all defined SecureForge requirements are present."""
loader = RequirementLoader()

```
requirements = loader.load_file(
    REQUIREMENTS_FILE
)

requirement_ids = {
    requirement.requirement_id
    for requirement in requirements
}

assert requirement_ids == EXPECTED_REQUIREMENTS
```

def test_repository_requirements_have_unique_ids() -> None:
"""Verify requirement identifiers are unique."""
loader = RequirementLoader()

```
requirements = loader.load_file(
    REQUIREMENTS_FILE
)

requirement_ids = [
    requirement.requirement_id
    for requirement in requirements
]

assert len(requirement_ids) == len(
    set(requirement_ids)
)
```

def test_repository_requirements_are_active() -> None:
"""Verify all baseline requirements are active."""
loader = RequirementLoader()

```
requirements = loader.load_file(
    REQUIREMENTS_FILE
)

assert all(
    requirement.status == RequirementStatus.ACTIVE
    for requirement in requirements
)
```

def test_repository_requirements_have_descriptions() -> None:
"""Verify requirements contain useful descriptions."""
loader = RequirementLoader()

```
requirements = loader.load_file(
    REQUIREMENTS_FILE
)

assert all(
    requirement.description.strip()
    for requirement in requirements
)
```

def test_repository_requirements_have_verification_methods() -> None:
"""Verify requirements define at least one verification method."""
loader = RequirementLoader()

```
requirements = loader.load_file(
    REQUIREMENTS_FILE
)

assert all(
    requirement.verification_methods
    for requirement in requirements
)
```

def test_repository_mandatory_requirements_are_security_relevant() -> None:
"""Verify mandatory requirements use expected security categories."""
loader = RequirementLoader()

```
requirements = loader.load_file(
    REQUIREMENTS_FILE
)

mandatory = [
    requirement
    for requirement in requirements
    if requirement.mandatory
]

assert mandatory

allowed_categories = {
    RequirementCategory.AUTHENTICATION,
    RequirementCategory.AUTHORIZATION,
    RequirementCategory.API,
    RequirementCategory.INPUT,
    RequirementCategory.SECRET,
    RequirementCategory.DEPENDENCY,
    RequirementCategory.CONTAINER,
    RequirementCategory.INFRASTRUCTURE,
    RequirementCategory.TRANSPORT,
}

assert all(
    requirement.category in allowed_categories
    for requirement in mandatory
)
```

def test_repository_authorization_requirements_cover_regression() -> None:
"""Verify authorization requirements support regression testing."""
loader = RequirementLoader()

```
requirements = loader.load_file(
    REQUIREMENTS_FILE
)

authorization_requirements = [
    requirement
    for requirement in requirements
    if requirement.category
    == RequirementCategory.AUTHORIZATION
]

assert authorization_requirements

assert all(
    "regression" in requirement.verification_methods
    for requirement in authorization_requirements
)
```

def test_repository_injection_requirement_supports_regression() -> None:
"""Verify injection protection can be regression-tested."""
loader = RequirementLoader()

```
requirements = loader.load_file(
    REQUIREMENTS_FILE
)

injection_requirement = next(
    requirement
    for requirement in requirements
    if requirement.requirement_id
    == "SF-INPUT-001"
)

assert (
    "regression"
    in injection_requirement.verification_methods
)
```

def test_repository_regression_requirement_exists() -> None:
"""Verify SecureForge explicitly models regression protection."""
loader = RequirementLoader()

```
requirements = loader.load_file(
    REQUIREMENTS_FILE
)

regression_requirement = next(
    requirement
    for requirement in requirements
    if requirement.requirement_id
    == "SF-REG-001"
)

assert (
    regression_requirement.category
    == RequirementCategory.REGRESSION
)

assert regression_requirement.mandatory is False
```
