"""Tests for the SecureForge normalization adapter registry."""

import pytest

from secureforge.core.normalization import (
    NormalizationAdapter,
    NormalizationRegistry,
)


class TestAdapter(NormalizationAdapter):
    """Test normalization adapter."""

    source_name = "test-scanner"

    def parse(self, raw_evidence):
        """Parse test evidence."""
        raise NotImplementedError


class SecondTestAdapter(NormalizationAdapter):
    """Second test normalization adapter."""

    source_name = "second-scanner"

    def parse(self, raw_evidence):
        """Parse test evidence."""
        raise NotImplementedError


def test_registry_starts_empty() -> None:
    """Verify a new registry contains no adapters."""
    registry = NormalizationRegistry()

    assert len(registry) == 0
    assert registry.sources() == []
    assert registry.all() == []


def test_adapter_can_be_registered() -> None:
    """Verify an adapter can be registered."""
    registry = NormalizationRegistry()
    adapter = TestAdapter()

    registry.register(adapter)

    assert len(registry) == 1
    assert registry.contains("test-scanner") is True
    assert registry.get("test-scanner") is adapter


def test_source_lookup_is_case_insensitive() -> None:
    """Verify source lookup normalizes case."""
    registry = NormalizationRegistry()
    adapter = TestAdapter()

    registry.register(adapter)

    assert registry.get("TEST-SCANNER") is adapter
    assert registry.get("Test-Scanner") is adapter


def test_source_lookup_ignores_whitespace() -> None:
    """Verify source lookup normalizes surrounding whitespace."""
    registry = NormalizationRegistry()
    adapter = TestAdapter()

    registry.register(adapter)

    assert registry.get("  test-scanner  ") is adapter


def test_duplicate_registration_is_rejected() -> None:
    """Verify duplicate source names cannot be registered silently."""
    registry = NormalizationRegistry()

    registry.register(TestAdapter())

    with pytest.raises(
        ValueError,
        match="already registered",
    ):
        registry.register(TestAdapter())


def test_duplicate_registration_can_replace_adapter() -> None:
    """Verify explicit replacement is supported."""
    registry = NormalizationRegistry()

    original = TestAdapter()
    replacement = TestAdapter()

    registry.register(original)
    registry.register(
        replacement,
        replace=True,
    )

    assert registry.get("test-scanner") is replacement
    assert len(registry) == 1


def test_multiple_adapters_can_be_registered() -> None:
    """Verify batch registration."""
    registry = NormalizationRegistry()

    count = registry.register_many(
        [
            TestAdapter(),
            SecondTestAdapter(),
        ]
    )

    assert count == 2
    assert len(registry) == 2
    assert registry.sources() == [
        "test-scanner",
        "second-scanner",
    ]


def test_register_many_supports_replacement() -> None:
    """Verify batch registration can replace existing adapters."""
    registry = NormalizationRegistry()

    registry.register(TestAdapter())

    replacement = TestAdapter()

    count = registry.register_many(
        [replacement],
        replace=True,
    )

    assert count == 1
    assert registry.get("test-scanner") is replacement


def test_require_returns_registered_adapter() -> None:
    """Verify require returns an existing adapter."""
    registry = NormalizationRegistry()
    adapter = TestAdapter()

    registry.register(adapter)

    assert registry.require("test-scanner") is adapter


def test_require_raises_for_unknown_source() -> None:
    """Verify missing adapters produce a useful error."""
    registry = NormalizationRegistry()

    with pytest.raises(
        KeyError,
        match="No normalization adapter is registered",
    ):
        registry.require("unknown-scanner")


def test_contains_returns_false_for_unknown_source() -> None:
    """Verify unknown sources are not reported as registered."""
    registry = NormalizationRegistry()

    assert registry.contains("unknown-scanner") is False


def test_remove_returns_registered_adapter() -> None:
    """Verify an adapter can be removed."""
    registry = NormalizationRegistry()
    adapter = TestAdapter()

    registry.register(adapter)

    removed = registry.remove("test-scanner")

    assert removed is adapter
    assert len(registry) == 0
    assert registry.contains("test-scanner") is False


def test_remove_unknown_source_raises() -> None:
    """Verify removing an unknown source raises an error."""
    registry = NormalizationRegistry()

    with pytest.raises(
        KeyError,
        match="No normalization adapter is registered",
    ):
        registry.remove("unknown-scanner")


def test_clear_removes_all_adapters() -> None:
    """Verify the registry can be reset."""
    registry = NormalizationRegistry()

    registry.register_many(
        [
            TestAdapter(),
            SecondTestAdapter(),
        ]
    )

    registry.clear()

    assert len(registry) == 0
    assert registry.sources() == []
    assert registry.all() == []


def test_empty_source_name_is_rejected() -> None:
    """Verify adapters cannot register without a source name."""
    adapter = TestAdapter()
    adapter.source_name = "   "

    registry = NormalizationRegistry()

    with pytest.raises(
        ValueError,
        match="source name cannot be empty",
    ):
        registry.register(adapter)


def test_sources_preserve_registration_order() -> None:
    """Verify source ordering is deterministic."""
    registry = NormalizationRegistry()

    registry.register(SecondTestAdapter())
    registry.register(TestAdapter())

    assert registry.sources() == [
        "second-scanner",
        "test-scanner",
    ]
