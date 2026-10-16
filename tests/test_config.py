"""Tests for SecureForge canonical configuration models."""

from secureforge.core.config import (
    ScanConfiguration,
    ScanProfile,
    TargetConfiguration,
    TargetType,
    ToolConfiguration,
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
