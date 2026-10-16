# SecureForge runtime factory tests

from pathlib import Path

from secureforge.config.runtime import (
    SecureForgeRuntime,
    build_runtime,
)
from secureforge.config.runtime_factory import (
    load_scan_configuration,
)
from secureforge.core.config import (
    ScanConfiguration,
    ScanProfile,
)


CONFIG_DIR = (
    Path(__file__).resolve().parents[1]
    / "secureforge"
    / "config"
)


def test_build_runtime_returns_secureforge_runtime() -> None:
    runtime = build_runtime(
        profile="quick",
    )

    assert isinstance(
        runtime,
        SecureForgeRuntime,
    )


def test_build_runtime_creates_orchestrator() -> None:
    runtime = build_runtime(
        profile="quick",
    )

    assert runtime.orchestrator is not None


def test_build_runtime_creates_scan_store() -> None:
    runtime = build_runtime(
        profile="quick",
    )

    assert runtime.store is not None


def test_build_runtime_creates_pipeline() -> None:
    runtime = build_runtime(
        profile="quick",
    )

    assert runtime.pipeline is not None


def test_build_runtime_supports_standard_profile() -> None:
    runtime = build_runtime(
        profile="standard",
    )

    assert runtime.orchestrator is not None
    assert runtime.pipeline is not None


def test_build_runtime_supports_full_profile() -> None:
    runtime = build_runtime(
        profile="full",
    )

    assert runtime.orchestrator is not None
    assert runtime.pipeline is not None


def test_load_quick_profile_builds_canonical_configuration() -> None:
    configuration = load_scan_configuration(
        CONFIG_DIR / "quick.yaml"
    )

    assert isinstance(
        configuration,
        ScanConfiguration,
    )
    assert configuration.profile is ScanProfile.QUICK
    assert configuration.application == "SecureCommerce"
    assert configuration.version == "0.1.0"
    assert configuration.environment == "lab"

    assert configuration.target.source_path == (
        "./vulnerable-app/securecommerce"
    )

    assert [
        tool.name
        for tool in configuration.tools
    ] == [
        "sast",
        "sca",
        "secrets",
    ]

    assert configuration.tools[0].command == [
        "sast-scanner",
        "--source",
        "{source_path}",
        "--format",
        "json",
    ]


def test_load_standard_profile_builds_canonical_configuration() -> None:
    configuration = load_scan_configuration(
        CONFIG_DIR / "standard.yaml"
    )

    assert isinstance(
        configuration,
        ScanConfiguration,
    )
    assert configuration.profile is ScanProfile.STANDARD
    assert configuration.application == "SecureCommerce"

    assert configuration.target.base_url == (
        "http://localhost:5000"
    )
    assert configuration.target.api_base_url == (
        "http://localhost:5000/api"
    )
    assert configuration.target.openapi_url == (
        "http://localhost:5000/openapi.json"
    )
    assert configuration.target.source_path == (
        "./vulnerable-app/securecommerce"
    )
    assert configuration.target.container_image == (
        "securecommerce:latest"
    )

    assert [
        tool.name
        for tool in configuration.tools
    ] == [
        "sast",
        "sca",
        "secrets",
        "api",
        "dast",
        "container",
    ]

    commands = {
        tool.name: tool.command
        for tool in configuration.tools
    }

    assert commands["api"] == [
        "api-security-scanner",
        "--openapi",
        "{openapi_url}",
        "--format",
        "json",
    ]
    assert commands["dast"] == [
        "dast-scanner",
        "--target",
        "{base_url}",
        "--format",
        "json",
    ]
    assert commands["container"] == [
        "container-scanner",
        "--target",
        "{container_image}",
        "--format",
        "json",
    ]


def test_load_full_profile_builds_canonical_configuration() -> None:
    configuration = load_scan_configuration(
        CONFIG_DIR / "full.yaml"
    )

    assert isinstance(
        configuration,
        ScanConfiguration,
    )
    assert configuration.profile is ScanProfile.FULL
    assert configuration.application == "SecureCommerce"

    assert configuration.target.base_url == (
        "http://localhost:5000"
    )
    assert configuration.target.api_base_url == (
        "http://localhost:5000/api"
    )
    assert configuration.target.openapi_url == (
        "http://localhost:5000/openapi.json"
    )
    assert configuration.target.source_path == (
        "./vulnerable-app/securecommerce"
    )
    assert configuration.target.container_image == (
        "securecommerce:latest"
    )
    assert configuration.target.iac_path == (
        "./vulnerable-app/securecommerce/infra"
    )
    assert configuration.target.network_target == (
        "127.0.0.1"
    )
    assert configuration.target.evidence_path == (
        "./evidence"
    )

    assert [
        tool.name
        for tool in configuration.tools
    ] == [
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

    commands = {
        tool.name: tool.command
        for tool in configuration.tools
    }

    assert commands["iac"] == [
        "iac-scanner",
        "--path",
        "{iac_path}",
        "--format",
        "json",
    ]
    assert commands["nessus"] == [
        "nessus-scanner",
        "--target",
        "{network_target}",
        "--format",
        "json",
    ]
    assert commands["nmap"] == [
        "nmap",
        "-sV",
        "-oX",
        "-",
        "{network_target}",
    ]

    manual = next(
        tool
        for tool in configuration.tools
        if tool.name == "manual"
    )

    assert manual.enabled is True
    assert manual.metadata == {}
    assert configuration.integrations["manual"].options[
        "evidence_path"
    ] == "./evidence/manual.json"
