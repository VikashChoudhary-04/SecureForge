"""Tests for SecureForge configuration and scan profiles."""

import pytest

from secureforge.core.config import (
FULL_PROFILE,
QUICK_PROFILE,
STANDARD_PROFILE,
ScanConfiguration,
ScanProfile,
TargetConfiguration,
TargetType,
ToolConfiguration,
get_profile,
list_profiles,
)

def build_target() -> TargetConfiguration:
"""Create a representative SecureCommerce target."""
return TargetConfiguration(
name="SecureCommerce",
target_type=TargetType.WEB_AND_API,
base_url="http://localhost:8000",
api_base_url="http://localhost:8000/api",
openapi_url="http://localhost:8000/openapi.json",
source_path="vulnerable-app/securecommerce",
)

def build_scan_configuration(
*,
profile: ScanProfile = ScanProfile.QUICK,
) -> ScanConfiguration:
"""Create a representative SecureForge scan configuration."""
return ScanConfiguration(
application="SecureCommerce",
version="1.0.0",
profile=profile,
environment="lab",
target=build_target(),
tools=[
ToolConfiguration(
name="semgrep",
enabled=True,
executable="semgrep",
timeout_seconds=120,
),
ToolConfiguration(
name="trivy",
enabled=False,
executable="trivy",
),
],
output_directory="reports",
)

def test_target_configuration_stores_application_target() -> None:
"""Verify target metadata is stored correctly."""
target = build_target()


assert target.name == "SecureCommerce"
assert target.target_type == TargetType.WEB_AND_API
assert target.base_url == "http://localhost:8000"
assert target.api_base_url == "http://localhost:8000/api"
assert target.openapi_url == "http://localhost:8000/openapi.json"


def test_web_and_api_target_reports_both_capabilities() -> None:
"""Verify a combined target is recognized as both web and API."""
target = build_target()


assert target.target_type == TargetType.WEB_AND_API


def test_scan_configuration_defaults_to_quick_profile() -> None:
"""Verify the default scan profile."""
configuration = ScanConfiguration(
application="SecureCommerce",
version="1.0.0",
target=build_target(),
)


assert configuration.profile == ScanProfile.QUICK
assert configuration.environment == "lab"
assert configuration.output_directory == "reports"


def test_enabled_tools_are_filtered() -> None:
"""Verify disabled tools are excluded from active tools."""
configuration = build_scan_configuration()


enabled_tools = configuration.enabled_tools

assert len(enabled_tools) == 1
assert enabled_tools[0].name == "semgrep"


def test_web_target_detection() -> None:
"""Verify web target detection."""
configuration = build_scan_configuration()


assert configuration.has_web_target() is True


def test_api_target_detection() -> None:
"""Verify API target detection."""
configuration = build_scan_configuration()


assert configuration.has_api_target() is True


def test_quick_profile_contains_expected_integrations() -> None:
"""Verify the quick profile scope."""
profile = get_profile(ScanProfile.QUICK)


assert profile == QUICK_PROFILE
assert profile.integrations == (
    "sast",
    "sca",
    "secrets",
)
assert profile.validation_enabled is False
assert profile.regression_enabled is False


def test_standard_profile_contains_expected_integrations() -> None:
"""Verify the standard profile scope."""
profile = get_profile("standard")


assert profile == STANDARD_PROFILE
assert "sast" in profile.integrations
assert "sca" in profile.integrations
assert "secrets" in profile.integrations
assert "api" in profile.integrations
assert "dast" in profile.integrations
assert "container" in profile.integrations
assert profile.validation_enabled is True
assert profile.regression_enabled is True


def test_full_profile_contains_infrastructure_integrations() -> None:
"""Verify the full profile includes broader assessment coverage."""
profile = get_profile(ScanProfile.FULL)


assert profile == FULL_PROFILE
assert "iac" in profile.integrations
assert "nessus" in profile.integrations
assert "nmap" in profile.integrations
assert "manual" in profile.integrations
assert profile.validation_enabled is True
assert profile.regression_enabled is True


def test_profile_lookup_accepts_case_insensitive_string() -> None:
"""Verify profile names can be supplied as strings."""
assert get_profile("QUICK") == QUICK_PROFILE
assert get_profile("Standard") == STANDARD_PROFILE
assert get_profile("FULL") == FULL_PROFILE

def test_invalid_profile_is_rejected() -> None:
"""Verify unsupported profile names raise a clear error."""
with pytest.raises(
ValueError,
match="Unsupported scan profile",
):
get_profile("enterprise")

def test_all_profiles_are_listed() -> None:
"""Verify all supported scan profiles are available."""
profiles = list_profiles()


assert len(profiles) == 3
assert {
    profile.profile
    for profile in profiles
} == {
    ScanProfile.QUICK,
    ScanProfile.STANDARD,
    ScanProfile.FULL,
}


def test_tool_configuration_supports_command_arguments() -> None:
"""Verify external tool configuration can store execution details."""
tool = ToolConfiguration(
name="nmap",
executable="nmap",
command=["nmap"],
arguments=[
"-sV",
"localhost",
],
timeout_seconds=60,
environment={
"MODE": "lab",
},
)


assert tool.name == "nmap"
assert tool.executable == "nmap"
assert tool.command == ["nmap"]
assert tool.arguments == [
    "-sV",
    "localhost",
]
assert tool.timeout_seconds == 60
assert tool.environment["MODE"] == "lab"


def test_scan_profile_can_be_explicitly_selected() -> None:
"""Verify a scan configuration preserves the selected profile."""
configuration = build_scan_configuration(
profile=ScanProfile.FULL,
)


assert configuration.profile == ScanProfile.FULL


def test_target_can_be_web_only() -> None:
"""Verify a web-only target does not report API capability."""
target = TargetConfiguration(
name="SecureCommerce Web",
target_type=TargetType.WEB,
base_url="http://localhost:8000",
)


configuration = ScanConfiguration(
    application="SecureCommerce",
    version="1.0.0",
    target=target,
)

assert configuration.has_web_target() is True
assert configuration.has_api_target() is False


def test_target_can_be_api_only() -> None:
"""Verify an API-only target does not report web capability."""
target = TargetConfiguration(
name="SecureCommerce API",
target_type=TargetType.API,
api_base_url="http://localhost:8000/api",
)


configuration = ScanConfiguration(
    application="SecureCommerce",
    version="1.0.0",
    target=target,
)

assert configuration.has_web_target() is False
assert configuration.has_api_target() is True

