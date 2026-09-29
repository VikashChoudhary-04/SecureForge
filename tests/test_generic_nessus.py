"""Tests for the generic Nessus integration."""

from __future__ import annotations

import pytest

from secureforge.integrations.base import (
    IntegrationConfigurationError,
    IntegrationParseError,
)
from secureforge.integrations.nessus import (
    GenericNessusIntegration,
)


@pytest.fixture()
def integration() -> GenericNessusIntegration:
    """Return a Nessus integration instance."""
    return GenericNessusIntegration()


def test_build_command(
    integration: GenericNessusIntegration,
) -> None:
    """The default command should target the configured host."""
    command = integration.build_command(
        {
            "network_target": "10.10.10.20",
        }
    )

    assert command == [
        "nessus-scanner",
        "--target",
        "10.10.10.20",
        "--format",
        "json",
    ]


def test_build_command_supports_host(
    integration: GenericNessusIntegration,
) -> None:
    """A host can be used when network_target is absent."""
    command = integration.build_command(
        {
            "host": "app.internal",
        }
    )

    assert command[2] == "app.internal"


def test_build_command_supports_custom_string(
    integration: GenericNessusIntegration,
) -> None:
    """A custom Nessus command should support target substitution."""
    command = integration.build_command(
        {
            "network_target": "10.0.0.5",
            "nessus_command": (
                "nessus-custom --target {target} --format json"
            ),
        }
    )

    assert command == [
        "nessus-custom",
        "--target",
        "10.0.0.5",
        "--format",
        "json",
    ]


def test_build_command_supports_custom_list(
    integration: GenericNessusIntegration,
) -> None:
    """A custom command supplied as a list should be supported."""
    command = integration.build_command(
        {
            "host": "server.internal",
            "nessus_command": [
                "nessus-custom",
                "--target",
                "{target}",
            ],
        }
    )

    assert command == [
        "nessus-custom",
        "--target",
        "server.internal",
    ]


def test_build_command_requires_target(
    integration: GenericNessusIntegration,
) -> None:
    """A target is required for Nessus execution."""
    with pytest.raises(
        IntegrationConfigurationError
    ):
        integration.build_command({})


def test_validate_config_requires_target(
    integration: GenericNessusIntegration,
) -> None:
    """Configuration validation should require a target."""
    with pytest.raises(
        IntegrationConfigurationError
    ):
        integration.validate_config({})


def test_supports_target(
    integration: GenericNessusIntegration,
) -> None:
    """The integration should identify supported targets."""
    assert integration.supports_target(
        {
            "network_target": "192.168.1.10"
        }
    )
    assert integration.supports_target(
        {
            "host": "server.internal"
        }
    )
    assert integration.supports_target(
        {
            "url": "https://example.internal"
        }
    )
    assert not integration.supports_target({})


def test_normalize_json_finding(
    integration: GenericNessusIntegration,
) -> None:
    """A Nessus JSON vulnerability should normalize correctly."""
    output = """
{
"findings": [
{
"plugin_id": "12345",
"plugin_name": "Outdated Web Server",
"severity": "3",
"host": "10.10.10.20",
"port": "443",
"protocol": "tcp",
"cve": "CVE-2026-12345",
"cvss": 8.8,
"cwe": "CWE-79",
"description": "The installed web server is vulnerable.",
"solution": "Upgrade to the vendor-fixed version.",
"plugin_output": "Detected vulnerable version 1.2.3."
}
]
}
"""

    findings = integration.normalize(
        output,
        target={
            "network_target": "10.10.10.20"
        },
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding["finding_id"] == "nessus-12345"
    assert finding["source_finding_id"] == "12345"
    assert finding["title"] == "Outdated Web Server"
    assert finding["severity"] == "high"
    assert finding["confidence"] == "high"
    assert finding["cwe"] == "CWE-79"
    assert finding["endpoint"] == (
        "tcp://10.10.10.20:443"
    )
    assert finding["metadata"]["cve"] == (
        "CVE-2026-12345"
    )
    assert finding["metadata"]["cvss"] == 8.8
    assert finding["evidence"] == (
        "Detected vulnerable version 1.2.3."
    )


def test_normalize_cve_from_text(
    integration: GenericNessusIntegration,
) -> None:
    """A CVE embedded in text should be extracted."""
    output = """
{
"findings": [
{
"plugin_id": "9001",
"plugin_name": "Example vulnerability",
"severity": "high",
"description": "Affected by CVE-2026-54321."
}
]
}
"""

    findings = integration.normalize(
        output
    )

    assert findings[0]["metadata"]["cve"] == (
        "CVE-2026-54321"
    )


def test_normalize_cvss_nested_object(
    integration: GenericNessusIntegration,
) -> None:
    """Nested CVSS objects should be supported."""
    output = """
{
"findings": [
{
"plugin_id": "9002",
"plugin_name": "Nested CVSS finding",
"severity": "medium",
"cvss": {
"base_score": 6.5
}
}
]
}
"""

    findings = integration.normalize(
        output
    )

    assert findings[0]["metadata"]["cvss"] == 6.5


def test_severity_normalization(
    integration: GenericNessusIntegration,
) -> None:
    """Nessus numeric and textual severities should normalize."""
    output = """
{
"findings": [
{"plugin_id": "1", "name": "Critical", "severity": "4"},
{"plugin_id": "2", "name": "High", "severity": "3"},
{"plugin_id": "3", "name": "Medium", "severity": "2"},
{"plugin_id": "4", "name": "Low", "severity": "1"},
{"plugin_id": "5", "name": "Info", "severity": "0"}
]
}
"""

    findings = integration.normalize(
        output
    )

    assert [
        item["severity"]
        for item in findings
    ] == [
        "critical",
        "high",
        "medium",
        "low",
        "info",
    ]


def test_requirement_mapping(
    integration: GenericNessusIntegration,
) -> None:
    """Common security categories should map to requirements."""
    output = """
{
"findings": [
{
"plugin_id": "ssl-1",
"name": "Weak TLS configuration",
"severity": "high"
},
{
"plugin_id": "auth-1",
"name": "Weak authentication configuration",
"severity": "high"
},
{
"plugin_id": "input-1",
"name": "SQL injection detected",
"severity": "critical"
},
{
"plugin_id": "authz-1",
"name": "Improper access control",
"severity": "high"
}
]
}
"""

    findings = integration.normalize(
        output
    )

    assert findings[0][
        "security_requirement"
    ] == "SF-TRANSPORT-001"
    assert findings[1][
        "security_requirement"
    ] == "SF-AUTH-001"
    assert findings[2][
        "security_requirement"
    ] == "SF-INPUT-001"
    assert findings[3][
        "security_requirement"
    ] == "SF-AUTHZ-001"


def test_unknown_finding_does_not_invent_requirement(
    integration: GenericNessusIntegration,
) -> None:
    """Unknown findings should not receive a fabricated requirement."""
    output = """
{
"findings": [
{
"plugin_id": "7777",
"name": "Unclassified finding",
"severity": "low"
}
]
}
"""

    findings = integration.normalize(
        output
    )

    assert findings[0][
        "security_requirement"
    ] is None


def test_normalize_xml_report(
    integration: GenericNessusIntegration,
) -> None:
    """Nessus ReportItem XML should normalize correctly."""
    output = """
<NessusClientData_v2>
<Report>
<ReportHost name="10.10.10.30">
<ReportItem
port="443"
protocol="tcp"
svc_name="https"
pluginID="2468"
pluginName="Weak TLS Configuration"
severity="2">
<description>TLS configuration is weak.</description>
<solution>Use modern TLS configuration.</solution>
<plugin_output>Weak cipher detected.</plugin_output>
<cve>CVE-2026-11111</cve>
<cvss3_base_score>6.5</cvss3_base_score>
</ReportItem>
</ReportHost>
</Report>
</NessusClientData_v2>
"""

    findings = integration.normalize(
        output,
        target={
            "network_target": "10.10.10.30"
        },
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding["finding_id"] == "nessus-2468"
    assert finding["title"] == (
        "Weak TLS Configuration"
    )
    assert finding["severity"] == "medium"
    assert finding["endpoint"] == (
        "tcp://10.10.10.30:443"
    )
    assert finding["metadata"]["cve"] == (
        "CVE-2026-11111"
    )
    assert finding["metadata"]["cvss"] == 6.5


def test_empty_output_fails(
    integration: GenericNessusIntegration,
) -> None:
    """Empty Nessus output should fail clearly."""
    with pytest.raises(
        IntegrationParseError
    ):
        integration.normalize("")


def test_invalid_json_fails(
    integration: GenericNessusIntegration,
) -> None:
    """Invalid JSON should produce a parse error."""
    with pytest.raises(
        IntegrationParseError
    ):
        integration.normalize(
            "{invalid-json}"
        )


def test_unsupported_json_structure_fails(
    integration: GenericNessusIntegration,
) -> None:
    """Unsupported JSON structures should produce a parse error."""
    with pytest.raises(
        IntegrationParseError
    ):
        integration.normalize(
            '{"metadata": {"scanner": "nessus"}}'
        )


def test_non_dict_json_finding_is_skipped(
    integration: GenericNessusIntegration,
) -> None:
    """Malformed individual list entries should not crash parsing."""
    output = """
[
"invalid finding",
{
"plugin_id": "123",
"name": "Valid finding",
"severity": "low"
}
]
"""

    findings = integration.normalize(
        output
    )

    assert len(findings) == 1
    assert findings[0]["finding_id"] == (
        "nessus-123"
    )


def test_metadata_preserves_nessus_fields(
    integration: GenericNessusIntegration,
) -> None:
    """Useful scanner metadata should be preserved."""
    output = """
{
"findings": [
{
"plugin_id": "5000",
"plugin_name": "Known vulnerability",
"severity": "high",
"family": "Web Servers",
"service": "https",
"product": "Example Server",
"version": "1.2.3",
"exploit_available": true,
"vpr": 7.4
}
]
}
"""

    findings = integration.normalize(
        output
    )

    metadata = findings[0]["metadata"]

    assert metadata["family"] == "Web Servers"
    assert metadata["service"] == "https"
    assert metadata["product"] == "Example Server"
    assert metadata["version"] == "1.2.3"
    assert metadata["exploit_available"] is True
    assert metadata["vpr"] == 7.4


def test_default_remediation_mentions_cve(
    integration: GenericNessusIntegration,
) -> None:
    """CVE-backed findings should receive useful default remediation."""
    output = """
{
"findings": [
{
"plugin_id": "6000",
"name": "Vulnerable component",
"severity": "high",
"cve": "CVE-2026-99999"
}
]
}
"""

    findings = integration.normalize(
        output
    )

    assert "CVE-2026-99999" in (
        findings[0]["remediation"]
    )


def test_create_evidence(
    integration: GenericNessusIntegration,
) -> None:
    """Raw Nessus evidence should preserve source metadata."""
    evidence = integration.create_evidence(
        source_reference="reports/nessus.json",
        target="10.10.10.40",
        raw_data={
            "findings": []
        },
        metadata={
            "source_version": "10.8"
        },
    )

    assert evidence.source == "nessus"
    assert evidence.source_reference == (
        "reports/nessus.json"
    )
    assert evidence.target == "10.10.10.40"
    assert evidence.metadata["source_version"] == "10.8"
    assert evidence.metadata["integration"] == "nessus"


def test_xml_without_report_items_fails(
    integration: GenericNessusIntegration,
) -> None:
    """XML without supported ReportItem entries should fail."""
    output = """
<NessusClientData_v2>
<Report />
</NessusClientData_v2>
"""

    with pytest.raises(
        IntegrationParseError
    ):
        integration.normalize(
            output
        )
