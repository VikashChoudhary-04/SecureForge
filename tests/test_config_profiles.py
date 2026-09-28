"""Tests for SecureForge scan profiles."""

from __future__ import annotations

import pytest

from secureforge.config.profiles import (
    CI_PROFILE,
    FULL_PROFILE,
    QUICK_PROFILE,
    STANDARD_PROFILE,
    get_profile,
    list_profiles,
)


def test_quick_profile_definition() -> None:
    """The quick profile contains fast security integrations."""
    assert QUICK_PROFILE.name == "quick"
    assert QUICK_PROFILE.integrations == (
        "sast",
        "sca",
        "secrets",
    )


def test_standard_profile_definition() -> None:
    """The standard profile contains application security integrations."""
    assert STANDARD_PROFILE.name == "standard"
    assert STANDARD_PROFILE.integrations == (
        "sast",
        "sca",
        "secrets",
        "api",
        "dast",
        "container",
    )


def test_full_profile_definition() -> None:
    """The full profile contains deeper security integrations."""
    assert FULL_PROFILE.name == "full"
    assert FULL_PROFILE.integrations == (
        "sast",
        "sca",
        "secrets",
        "api",
        "dast",
        "container",
        "iac",
        "nessus",
        "nmap",
        "manual",
    )


def test_ci_profile_definition() -> None:
    """The CI profile uses only the deterministic CI integration."""
    assert CI_PROFILE.name == "ci"
    assert CI_PROFILE.integrations == ("ci",)


def test_get_profile_is_case_insensitive() -> None:
    """Profile lookup normalizes the requested name."""
    assert get_profile("CI") is CI_PROFILE
    assert get_profile(" Standard ") is STANDARD_PROFILE


def test_get_profile_rejects_unknown_profile() -> None:
    """Unknown profiles produce a clear configuration error."""
    with pytest.raises(ValueError, match="Unknown SecureForge profile"):
        get_profile("does-not-exist")


def test_list_profiles_contains_all_builtin_profiles() -> None:
    """All built-in profiles are exposed by the profile registry."""
    profiles = list_profiles()

    assert {profile.name for profile in profiles} == {
        "quick",
        "standard",
        "full",
        "ci",
    }
