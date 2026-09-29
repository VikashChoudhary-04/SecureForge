"""Tests for the generic container security integration."""

from __future__ import annotations

from secureforge.core.config import (
ScanConfiguration,
TargetConfiguration,
)
from secureforge.core.normalization import RawEvidence
from secureforge.integrations.container import (
GenericContainerIntegration,
)

def make_configuration(
*,
container_image: str | None = "securecommerce:latest",
container_path: str | None = None,
) -> ScanConfiguration:
"""Create a container-security scan configuration."""
return ScanConfiguration(
application="SecureCommerce",
target=TargetConfiguration(
name="securecommerce-container",
container_image=container_image,
container_path=container_path,
),
)

def make_evidence(
raw_data: dict,
*,
target: str = "securecommerce:latest",
) -> RawEvidence:
"""Create container scanner evidence."""
return RawEvidence(
source="container",
target=target,
raw_data=raw_data,
metadata={
"application": "SecureCommerce",
},
)

def test_build_command_uses_container_image() -> None:
integration = GenericContainerIntegration(
executable="trivy"
)


command = integration.build_command(
    make_configuration()
)

assert command == [
    "trivy",
    "--target",
    "securecommerce:latest",
    "--format",
    "json",
]


def test_build_command_uses_container_path_when_image_is_missing() -> None:
integration = GenericContainerIntegration(
executable="container-scanner"
)


command = integration.build_command(
    make_configuration(
        container_image=None,
        container_path="./Dockerfile",
    )
)

assert command == [
    "container-scanner",
    "--target",
    "./Dockerfile",
    "--format",
    "json",
]


def test_build_command_supports_custom_template() -> None:
integration = GenericContainerIntegration(
command=[
"custom-container-scanner",
"--image",
"{image}",
"--path",
"{path}",
"--target",
"{target}",
]
)


command = integration.build_command(
    make_configuration()
)

assert command == [
    "custom-container-scanner",
    "--image",
    "securecommerce:latest",
    "--path",
    "securecommerce:latest",
    "--target",
    "securecommerce:latest",
]


def test_build_command_requires_container_target() -> None:
integration = GenericContainerIntegration()


configuration = make_configuration(
    container_image=None,
    container_path=None,
)

try:
    integration.build_command(
        configuration
    )
except Exception as exc:
    assert "container_image" in str(exc)
else:
    raise AssertionError(
        "Expected container target validation to fail."
    )


def test_normalize_vulnerable_package() -> None:
integration = GenericContainerIntegration()


evidence = make_evidence(
    {
        "findings": [
            {
                "id": "CVE-2026-0001",
                "title": "Vulnerable OpenSSL Package",
                "type": "vulnerability",
                "severity": "high",
                "confidence": "high",
                "package": "openssl",
                "installed_version": "3.0.1",
                "fixed_version": "3.0.2",
                "cve": "CVE-2026-0001",
                "cvss": 8.1,
                "cwe": "1395",
            }
        ]
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True
assert len(result.findings) == 1

finding = result.findings[0]

assert finding["source_finding_id"] == "CVE-2026-0001"
assert finding["severity"] == "high"
assert finding["confidence"] == "high"
assert finding["cwe"] == "CWE-1395"
assert finding["security_requirement"] == (
    "SF-CONTAINER-001"
)
assert finding["metadata"]["package"] == "openssl"
assert finding["metadata"]["installed_version"] == "3.0.1"
assert finding["metadata"]["fixed_version"] == "3.0.2"
assert finding["metadata"]["cvss"] == 8.1


def test_fixed_version_generates_upgrade_remediation() -> None:
integration = GenericContainerIntegration()


evidence = make_evidence(
    {
        "vulnerabilities": [
            {
                "id": "CVE-2026-0002",
                "title": "Vulnerable Package",
                "type": "package vulnerability",
                "package": "libxml2",
                "installed_version": "2.9",
                "fixed_version": "2.11",
            }
        ]
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True

remediation = result.findings[0]["remediation"]

assert "libxml2" in remediation
assert "2.11" in remediation
assert "rebuild" in remediation.lower()


def test_root_container_maps_to_container_requirement() -> None:
integration = GenericContainerIntegration()


evidence = make_evidence(
    {
        "misconfigurations": [
            {
                "id": "container-001",
                "title": "Container Runs As Root",
                "type": "running as root",
                "severity": "high",
                "running_as_root": True,
            }
        ]
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True

finding = result.findings[0]

assert finding["security_requirement"] == (
    "SF-CONTAINER-001"
)
assert "non-root" in (
    finding["remediation"].lower()
)
assert "isolation" in (
    finding["impact"].lower()
)


def test_privileged_container_generates_privilege_remediation() -> None:
integration = GenericContainerIntegration()


evidence = make_evidence(
    {
        "findings": [
            {
                "id": "container-002",
                "title": "Privileged Container",
                "type": "privileged",
                "severity": "critical",
                "privileged": True,
            }
        ]
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True

remediation = result.findings[0]["remediation"]

assert "privileged" in remediation.lower()
assert "capabilities" in remediation.lower()


def test_exposed_port_finding() -> None:
integration = GenericContainerIntegration()


evidence = make_evidence(
    {
        "issues": [
            {
                "id": "container-003",
                "title": "Unnecessary Exposed Port",
                "type": "exposed port",
                "severity": "medium",
                "ports": [8080, 9000],
            }
        ]
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True

finding = result.findings[0]

assert finding["security_requirement"] == (
    "SF-CONTAINER-001"
)
assert finding["metadata"]["ports"] == [
    8080,
    9000,
]
assert "network" in (
    finding["remediation"].lower()
)


def test_custom_security_requirement_is_preserved() -> None:
integration = GenericContainerIntegration()


evidence = make_evidence(
    {
        "findings": [
            {
                "id": "container-004",
                "title": "Custom Container Finding",
                "security_requirement": "SF-CUSTOM-001",
            }
        ]
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True
assert result.findings[0][
    "security_requirement"
] == "SF-CUSTOM-001"


def test_image_metadata_is_preserved() -> None:
integration = GenericContainerIntegration()


evidence = make_evidence(
    {
        "findings": [
            {
                "id": "container-005",
                "title": "Image Issue",
                "image": "securecommerce:1.2.0",
                "layer": "sha256:abc123",
                "vendor": "example-vendor",
                "component": "openssl",
            }
        ]
    },
    target="securecommerce:1.2.0",
)

result = integration.normalize(
    evidence
)

assert result.success is True

finding = result.findings[0]

assert finding["asset"] == "securecommerce:1.2.0"
assert finding["metadata"]["image"] == (
    "securecommerce:1.2.0"
)
assert finding["metadata"]["layer"] == (
    "sha256:abc123"
)
assert finding["metadata"]["vendor"] == (
    "example-vendor"
)
assert finding["metadata"]["component"] == (
    "openssl"
)


def test_default_severity_is_medium() -> None:
integration = GenericContainerIntegration()


evidence = make_evidence(
    {
        "findings": [
            {
                "id": "container-006",
                "title": "Container Configuration Issue",
            }
        ]
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True
assert result.findings[0]["severity"] == "medium"


def test_default_confidence_is_unknown() -> None:
integration = GenericContainerIntegration()


evidence = make_evidence(
    {
        "findings": [
            {
                "id": "container-007",
                "title": "Container Configuration Issue",
            }
        ]
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True
assert result.findings[0]["confidence"] == "unknown"


def test_stdout_json_is_supported() -> None:
integration = GenericContainerIntegration()


evidence = make_evidence(
    {
        "stdout": (
            '[{"id":"container-008",'
            '"title":"Root Container",'
            '"type":"root"}]'
        )
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True
assert len(result.findings) == 1
assert (
    result.findings[0]["source_finding_id"]
    == "container-008"
)


def test_invalid_stdout_json_returns_failure() -> None:
integration = GenericContainerIntegration()


evidence = make_evidence(
    {
        "stdout": "not-json"
    }
)

result = integration.normalize(
    evidence
)

assert result.success is False
assert result.errors
assert "valid JSON" in result.errors[0]


def test_malformed_record_becomes_warning() -> None:
integration = GenericContainerIntegration()


evidence = make_evidence(
    {
        "findings": [
            "invalid-record",
            {
                "id": "container-009",
                "title": "Valid Finding",
            },
        ]
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True
assert len(result.findings) == 1
assert any(
    "not an object" in warning
    for warning in result.warnings
)


def test_multiple_container_findings_are_normalized() -> None:
integration = GenericContainerIntegration()


evidence = make_evidence(
    {
        "findings": [
            {
                "id": "container-010",
                "title": "Vulnerable Package",
                "type": "package vulnerability",
            },
            {
                "id": "container-011",
                "title": "Root Container",
                "type": "running as root",
            },
            {
                "id": "container-012",
                "title": "Exposed Port",
                "type": "exposed port",
            },
        ]
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True
assert len(result.findings) == 3

assert [
    finding["source_finding_id"]
    for finding in result.findings
] == [
    "container-010",
    "container-011",
    "container-012",
]


def test_integration_metadata() -> None:
integration = GenericContainerIntegration(
version="1.0.0"
)


metadata = integration.integration_metadata()

assert metadata["integration"] == "container"
assert metadata["display_name"] == (
    "Generic Container Security"
)
assert metadata["version"] == "1.0.0"

