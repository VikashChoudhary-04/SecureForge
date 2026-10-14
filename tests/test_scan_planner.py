"""Tests for the SecureForge scan planner."""

from __future__ import annotations

import pytest

from secureforge.core.config import (
    ScanConfiguration,
    ScanProfile,
    TargetConfiguration,
    TargetType,
    ToolConfiguration,
)
from secureforge.core.scan.planner import (
    PlannedTool,
    ScanPlanner,
)


def build_configuration(
    *,
    profile: ScanProfile = ScanProfile.QUICK,
    tools: list[ToolConfiguration] | None = None,
) -> ScanConfiguration:
    """Create a representative SecureForge configuration."""
    return ScanConfiguration(
        application="SecureCommerce",
        version="1.0.0",
        profile=profile,
        environment="lab",
        target=TargetConfiguration(
            name="securecommerce-local",
            target_type=TargetType.WEB_AND_API,
            base_url="http://localhost:5000",
            api_base_url="http://localhost:5000/api",
            openapi_url="http://localhost:5000/openapi.json",
            source_path="/workspace/securecommerce",
            container_image="securecommerce:latest",
            iac_path="/workspace/securecommerce/iac",
            network_target="127.0.0.1",
        ),
        tools=tools or [],
    )


def build_tool(
    name: str,
    *,
    enabled: bool = True,
) -> ToolConfiguration:
    """Create a representative tool configuration."""
    return ToolConfiguration(
        name=name,
        enabled=enabled,
        command=[
            "echo",
            name,
        ],
    )


def test_quick_profile_requires_expected_integrations() -> None:
    """Verify the quick profile integration set."""
    configuration = build_configuration(
        profile=ScanProfile.QUICK
    )

    planner = ScanPlanner()

    assert planner.required_integrations(
        configuration
    ) == (
        "sast",
        "sca",
        "secrets",
    )


def test_standard_profile_requires_expected_integrations() -> None:
    """Verify the standard profile integration set."""
    configuration = build_configuration(
        profile=ScanProfile.STANDARD
    )

    planner = ScanPlanner()

    assert planner.required_integrations(
        configuration
    ) == (
        "sast",
        "sca",
        "secrets",
        "api",
        "dast",
        "container",
    )


def test_full_profile_requires_expected_integrations() -> None:
    """Verify the full profile integration set."""
    configuration = build_configuration(
        profile=ScanProfile.FULL
    )

    planner = ScanPlanner()

    assert planner.required_integrations(
        configuration
    ) == (
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


def test_plan_selects_configured_enabled_tools() -> None:
    """Verify enabled configured tools are planned."""
    configuration = build_configuration(
        profile=ScanProfile.QUICK,
        tools=[
            build_tool("sast"),
            build_tool("sca"),
            build_tool("secrets"),
        ],
    )

    planned = ScanPlanner().plan(
        configuration
    )

    assert [
        item.integration
        for item in planned
    ] == [
        "sast",
        "sca",
        "secrets",
    ]


def test_plan_preserves_profile_order() -> None:
    """Verify planned tools follow profile order."""
    configuration = build_configuration(
        profile=ScanProfile.QUICK,
        tools=[
            build_tool("secrets"),
            build_tool("sast"),
            build_tool("sca"),
        ],
    )

    planned = ScanPlanner().plan(
        configuration
    )

    assert [
        item.integration
        for item in planned
    ] == [
        "sast",
        "sca",
        "secrets",
    ]


def test_plan_ignores_tools_not_in_profile() -> None:
    """Verify unrelated configured tools are not planned."""
    configuration = build_configuration(
        profile=ScanProfile.QUICK,
        tools=[
            build_tool("sast"),
            build_tool("sca"),
            build_tool("secrets"),
            build_tool("nmap"),
        ],
    )

    planned = ScanPlanner().plan(
        configuration
    )

    assert [
        item.integration
        for item in planned
    ] == [
        "sast",
        "sca",
        "secrets",
    ]


def test_plan_ignores_disabled_tools() -> None:
    """Verify disabled tools are excluded from execution."""
    configuration = build_configuration(
        profile=ScanProfile.QUICK,
        tools=[
            build_tool("sast"),
            build_tool("sca", enabled=False),
            build_tool("secrets"),
        ],
    )

    planned = ScanPlanner().plan(
        configuration
    )

    assert [
        item.integration
        for item in planned
    ] == [
        "sast",
        "secrets",
    ]


def test_plan_returns_empty_when_no_tools_are_configured() -> None:
    """Verify an empty configuration produces no plan entries."""
    configuration = build_configuration(
        profile=ScanProfile.QUICK
    )

    planned = ScanPlanner().plan(
        configuration
    )

    assert planned == []


def test_missing_integrations_are_reported() -> None:
    """Verify unconfigured profile integrations are identified."""
    configuration = build_configuration(
        profile=ScanProfile.QUICK,
        tools=[
            build_tool("sast"),
        ],
    )

    missing = ScanPlanner().missing_integrations(
        configuration
    )

    assert missing == [
        "sca",
        "secrets",
    ]


def test_no_missing_integrations_when_all_are_configured() -> None:
    """Verify a complete configuration has no missing integrations."""
    configuration = build_configuration(
        profile=ScanProfile.QUICK,
        tools=[
            build_tool("sast"),
            build_tool("sca"),
            build_tool("secrets"),
        ],
    )

    assert ScanPlanner().missing_integrations(
        configuration
    ) == []


def test_disabled_integrations_are_reported() -> None:
    """Verify explicitly disabled profile tools are identified."""
    configuration = build_configuration(
        profile=ScanProfile.QUICK,
        tools=[
            build_tool("sast"),
            build_tool("sca", enabled=False),
            build_tool("secrets"),
        ],
    )

    disabled = ScanPlanner().disabled_integrations(
        configuration
    )

    assert disabled == [
        "sca"
    ]


def test_disabled_integrations_do_not_count_as_missing() -> None:
    """Verify disabled tools are distinct from absent tools."""
    configuration = build_configuration(
        profile=ScanProfile.QUICK,
        tools=[
            build_tool("sast"),
            build_tool("sca", enabled=False),
            build_tool("secrets"),
        ],
    )

    planner = ScanPlanner()

    assert "sca" not in planner.missing_integrations(
        configuration
    )

    assert "sca" in planner.disabled_integrations(
        configuration
    )


def test_tool_names_are_case_insensitive() -> None:
    """Verify integration lookup ignores tool-name casing."""
    configuration = build_configuration(
        profile=ScanProfile.QUICK,
        tools=[
            build_tool("SAST"),
            build_tool("SCA"),
            build_tool("SECRETS"),
        ],
    )

    planned = ScanPlanner().plan(
        configuration
    )

    assert [
        item.integration
        for item in planned
    ] == [
        "sast",
        "sca",
        "secrets",
    ]


def test_planned_tool_contains_rendered_configuration() -> None:
    """Verify planned entries contain rendered tool configuration."""
    sast = ToolConfiguration(
        name="sast",
        enabled=True,
        command=[
            "sast-scanner",
            "--source",
            "{source_path}",
        ],
    )

    configuration = build_configuration(
        profile=ScanProfile.QUICK,
        tools=[
            sast,
            build_tool("sca"),
            build_tool("secrets"),
        ],
    )

    planned = ScanPlanner().plan(
        configuration
    )

    assert isinstance(
        planned[0],
        PlannedTool,
    )

    assert planned[0].configuration is not sast

    assert planned[0].configuration.command == [
        "sast-scanner",
        "--source",
        "/workspace/securecommerce",
    ]


def test_standard_profile_plans_only_available_tools() -> None:
    """Verify standard planning handles partial tool configuration."""
    configuration = build_configuration(
        profile=ScanProfile.STANDARD,
        tools=[
            build_tool("sast"),
            build_tool("dast"),
            build_tool("container"),
        ],
    )

    planned = ScanPlanner().plan(
        configuration
    )

    assert [
        item.integration
        for item in planned
    ] == [
        "sast",
        "dast",
        "container",
    ]

    assert ScanPlanner().missing_integrations(
        configuration
    ) == [
        "sca",
        "secrets",
        "api",
    ]


def test_full_profile_plans_available_integrations() -> None:
    """Verify full planning supports the complete integration set."""
    integration_names = [
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
    ]

    configuration = build_configuration(
        profile=ScanProfile.FULL,
        tools=[
            build_tool(name)
            for name in integration_names
        ],
    )

    planned = ScanPlanner().plan(
        configuration
    )

    assert [
        item.integration
        for item in planned
    ] == integration_names

    assert ScanPlanner().missing_integrations(
        configuration
    ) == []


def test_disabled_unrelated_tool_is_not_reported() -> None:
    """Verify unrelated disabled tools do not affect profile status."""
    configuration = build_configuration(
        profile=ScanProfile.QUICK,
        tools=[
            build_tool("sast"),
            build_tool("sca"),
            build_tool("secrets"),
            build_tool("nmap", enabled=False),
        ],
    )

    planner = ScanPlanner()

    assert planner.disabled_integrations(
        configuration
    ) == []

    assert planner.missing_integrations(
        configuration
    ) == []


def test_plan_returns_new_list_each_time() -> None:
    """Verify planning does not expose mutable internal state."""
    configuration = build_configuration(
        profile=ScanProfile.QUICK,
        tools=[
            build_tool("sast"),
            build_tool("sca"),
            build_tool("secrets"),
        ],
    )

    planner = ScanPlanner()

    first = planner.plan(configuration)
    second = planner.plan(configuration)

    assert first == second
    assert first is not second


@pytest.mark.parametrize(
    (
        "integration",
        "placeholder",
        "expected",
    ),
    [
        (
            "sast",
            "{source_path}",
            "/workspace/securecommerce",
        ),
        (
            "api",
            "{openapi_url}",
            "http://localhost:5000/openapi.json",
        ),
        (
            "dast",
            "{base_url}",
            "http://localhost:5000",
        ),
        (
            "container",
            "{container_image}",
            "securecommerce:latest",
        ),
        (
            "iac",
            "{iac_path}",
            "/workspace/securecommerce/iac",
        ),
        (
            "nessus",
            "{network_target}",
            "127.0.0.1",
        ),
    ],
)
def test_plan_renders_target_placeholders(
    integration: str,
    placeholder: str,
    expected: str,
) -> None:
    """Verify supported target placeholders are rendered by the planner."""
    configuration = build_configuration(
        profile=ScanProfile.FULL,
        tools=[
            ToolConfiguration(
                name=integration,
                enabled=True,
                command=[
                    "scanner",
                    "--target",
                    placeholder,
                ],
            )
        ],
    )

    planned = ScanPlanner().plan(
        configuration
    )

    assert len(planned) == 1

    assert planned[0].configuration.command == [
        "scanner",
        "--target",
        expected,
    ]


def test_plan_renders_multiple_placeholders_in_one_command() -> None:
    """Verify multiple target placeholders are rendered in one command."""
    configuration = build_configuration(
        profile=ScanProfile.FULL,
        tools=[
            ToolConfiguration(
                name="nmap",
                enabled=True,
                command=[
                    "scanner",
                    "{base_url}",
                    "{network_target}",
                    "{source_path}",
                ],
            )
        ],
    )

    planned = ScanPlanner().plan(
        configuration
    )

    assert planned[0].configuration.command == [
        "scanner",
        "http://localhost:5000",
        "127.0.0.1",
        "/workspace/securecommerce",
    ]


def test_plan_rejects_missing_target_value() -> None:
    """Verify missing target values fail planning explicitly."""
    configuration = build_configuration(
        profile=ScanProfile.FULL,
        tools=[
            ToolConfiguration(
                name="dast",
                enabled=True,
                command=[
                    "scanner",
                    "--target",
                    "{base_url}",
                ],
            )
        ],
    )

    configuration = configuration.model_copy(
        update={
            "target": configuration.target.model_copy(
                update={
                    "base_url": None,
                }
            )
        }
    )

    with pytest.raises(
        ValueError,
        match="base_url",
    ):
        ScanPlanner().plan(
            configuration
        )
