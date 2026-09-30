"""Tests for the SecureForge regression registry."""

from __future__ import annotations

import pytest

from secureforge.regression import (
    DuplicateRegressionTestError,
    RegressionRegistry,
    RegressionRegistryError,
    RegressionTest,
    RegressionTestNotFoundError,
)


def build_test(
    test_id: str,
    requirement: str = "SF-AUTHZ-001",
    enabled: bool = True,
) -> RegressionTest:
    """Build a representative regression test."""
    return RegressionTest(
        test_id=test_id,
        name=f"Regression {test_id}",
        security_requirement=requirement,
        description="Test security behavior.",
        objective="Prevent security regression.",
        target="/test",
        method="GET",
        expected_result="Secure response",
        failure_condition="Insecure response",
        enabled=enabled,
    )


def test_registry_registers_and_retrieves_test():
    """Registered tests should be retrievable by ID."""
    registry = RegressionRegistry()

    test = build_test("BOLA-001")

    registry.register(test)

    assert registry.contains("BOLA-001")
    assert registry.get("BOLA-001") is test
    assert registry.require("BOLA-001") is test
    assert len(registry) == 1


def test_registry_normalizes_test_id_lookup():
    """Test ID lookup should ignore surrounding whitespace."""
    registry = RegressionRegistry()

    test = build_test("BOLA-001")

    registry.register(test)

    assert registry.get(" BOLA-001 ") is test
    assert registry.contains(" BOLA-001 ")


def test_registry_rejects_empty_test_id():
    """An empty regression test ID should be rejected."""
    registry = RegressionRegistry()

    test = build_test("BOLA-001")
    test.test_id = "   "

    with pytest.raises(
        RegressionRegistryError,
        match="cannot be empty",
    ):
        registry.register(test)


def test_registry_rejects_duplicate_test_id():
    """Duplicate regression IDs should not overwrite existing tests."""
    registry = RegressionRegistry()

    registry.register(
        build_test("BOLA-001")
    )

    with pytest.raises(
        DuplicateRegressionTestError,
        match="already registered",
    ):
        registry.register(
            build_test("BOLA-001")
        )


def test_registry_register_many():
    """Multiple regression tests should be registered together."""
    registry = RegressionRegistry()

    tests = [
        build_test("BOLA-001"),
        build_test(
            "SQLI-001",
            requirement="SF-INPUT-001",
        ),
        build_test(
            "SECRET-001",
            requirement="SF-SECRET-001",
        ),
    ]

    registry.register_many(tests)

    assert len(registry) == 3
    assert [
        test.test_id
        for test in registry.all()
    ] == [
        "BOLA-001",
        "SQLI-001",
        "SECRET-001",
    ]


def test_registry_finds_tests_by_requirement():
    """Requirement lookup should return all mapped tests."""
    registry = RegressionRegistry(
        [
            build_test("BOLA-001"),
            build_test("BOLA-002"),
            build_test(
                "SQLI-001",
                requirement="SF-INPUT-001",
            ),
        ]
    )

    results = registry.for_requirement(
        "SF-AUTHZ-001"
    )

    assert [
        test.test_id
        for test in results
    ] == [
        "BOLA-001",
        "BOLA-002",
    ]


def test_registry_returns_enabled_tests():
    """Enabled lookup should exclude disabled tests."""
    registry = RegressionRegistry(
        [
            build_test(
                "BOLA-001",
                enabled=True,
            ),
            build_test(
                "SQLI-001",
                requirement="SF-INPUT-001",
                enabled=False,
            ),
            build_test(
                "XSS-001",
                requirement="SF-INPUT-001",
                enabled=True,
            ),
        ]
    )

    enabled = registry.enabled()

    assert [
        test.test_id
        for test in enabled
    ] == [
        "BOLA-001",
        "XSS-001",
    ]


def test_registry_require_raises_for_missing_test():
    """Missing required tests should raise a clear error."""
    registry = RegressionRegistry()

    with pytest.raises(
        RegressionTestNotFoundError,
        match="not registered",
    ):
        registry.require("BOLA-001")


def test_registry_get_returns_none_for_missing_test():
    """Optional lookup should return None for missing tests."""
    registry = RegressionRegistry()

    assert registry.get("BOLA-001") is None


def test_registry_remove_returns_removed_test():
    """Removing a test should return the removed definition."""
    registry = RegressionRegistry()

    test = build_test("BOLA-001")

    registry.register(test)

    removed = registry.remove("BOLA-001")

    assert removed is test
    assert registry.contains("BOLA-001") is False
    assert len(registry) == 0


def test_registry_remove_raises_for_missing_test():
    """Removing an unknown test should raise a clear error."""
    registry = RegressionRegistry()

    with pytest.raises(
        RegressionTestNotFoundError,
        match="not registered",
    ):
        registry.remove("BOLA-001")


def test_registry_clear_removes_all_tests():
    """Clear should remove every registered test."""
    registry = RegressionRegistry(
        [
            build_test("BOLA-001"),
            build_test("SQLI-001"),
        ]
    )

    registry.clear()

    assert len(registry) == 0
    assert registry.all() == []
