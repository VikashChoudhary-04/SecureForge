"""Registry for SecureForge security regression tests."""

from **future** import annotations

from collections.abc import Iterable

from .models import RegressionTest

class RegressionRegistryError(Exception):
"""Base exception for regression registry failures."""

class DuplicateRegressionTestError(
RegressionRegistryError
):
"""Raised when a regression test ID is registered twice."""

class RegressionTestNotFoundError(
RegressionRegistryError
):
"""Raised when a requested regression test does not exist."""

class RegressionRegistry:
"""Store and retrieve security regression tests."""

```
def __init__(
    self,
    tests: Iterable[RegressionTest] | None = None,
) -> None:
    self._tests: dict[str, RegressionTest] = {}

    if tests:
        self.register_many(tests)

def register(
    self,
    test: RegressionTest,
) -> None:
    """Register one regression test."""
    test_id = test.test_id.strip()

    if not test_id:
        raise RegressionRegistryError(
            "Regression test ID cannot be empty."
        )

    if test_id in self._tests:
        raise DuplicateRegressionTestError(
            f"Regression test '{test_id}' "
            "is already registered."
        )

    self._tests[test_id] = test

def register_many(
    self,
    tests: Iterable[RegressionTest],
) -> None:
    """Register multiple regression tests."""
    for test in tests:
        self.register(test)

def get(
    self,
    test_id: str,
) -> RegressionTest | None:
    """Return a regression test if registered."""
    return self._tests.get(
        test_id.strip()
    )

def require(
    self,
    test_id: str,
) -> RegressionTest:
    """Return a regression test or raise an error."""
    test = self.get(test_id)

    if test is None:
        raise RegressionTestNotFoundError(
            f"Regression test '{test_id}' "
            "is not registered."
        )

    return test

def for_requirement(
    self,
    security_requirement: str,
) -> list[RegressionTest]:
    """Return tests mapped to a security requirement."""
    requirement = security_requirement.strip()

    return [
        test
        for test in self._tests.values()
        if test.security_requirement
        == requirement
    ]

def all(
    self,
) -> list[RegressionTest]:
    """Return all registered regression tests."""
    return list(
        self._tests.values()
    )

def enabled(
    self,
) -> list[RegressionTest]:
    """Return all enabled regression tests."""
    return [
        test
        for test in self._tests.values()
        if test.enabled
    ]

def contains(
    self,
    test_id: str,
) -> bool:
    """Return whether a test is registered."""
    return test_id.strip() in self._tests

def remove(
    self,
    test_id: str,
) -> RegressionTest:
    """Remove and return a registered test."""
    normalized_id = test_id.strip()

    if normalized_id not in self._tests:
        raise RegressionTestNotFoundError(
            f"Regression test '{normalized_id}' "
            "is not registered."
        )

    return self._tests.pop(
        normalized_id
    )

def clear(self) -> None:
    """Remove all registered regression tests."""
    self._tests.clear()

def __len__(self) -> int:
    """Return the number of registered tests."""
    return len(self._tests)
```
