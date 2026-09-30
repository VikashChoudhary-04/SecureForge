"""Tests for the generic SecureForge SAST integration."""

import json

import pytest

from secureforge.core.config import (
    ScanConfiguration,
    ScanProfile,
    TargetConfiguration,
    TargetType,
    ToolConfiguration,
)
from secureforge.core.normalization import RawEvidence
from secureforge.integrations.base import (
    IntegrationConfigurationError,
    IntegrationParseError,
)
from secureforge.integrations.sast import (
    GenericSASTIntegration,
)


def build_configuration(
    *,
    source_path: str | None = "src",
    tools: list[ToolConfiguration] | None = None,
) -> ScanConfiguration:
    """Create a representative SAST configuration."""
    return ScanConfiguration(
        application="SecureCommerce",
        version="1.0.0",
        profile=ScanProfile.QUICK,
        environment="lab",
        target=TargetConfiguration(
            name="securecommerce-source",
            target_type=TargetType.WEB,
            source_path=source_path,
        ),
        tools=tools or [],
    )


def build_evidence(
    raw_data,
    *,
    application: str = "SecureCommerce",
    target: str = "src",
) -> RawEvidence:
    """Create representative SAST evidence."""
    return RawEvidence(
        source="sast",
        source_version="1.0.0",
        target=target,
        raw_data=raw_data,
        metadata={
            "application": application,
        },
    )


def build_finding(
    **overrides,
) -> dict:
    """Create a representative SAST scanner finding."""
    finding = {
        "id": "RULE-001",
        "title": "SQL Injection",
        "description": (
            "User-controlled input reaches a SQL query."
        ),
        "severity": "high",
        "confidence": "high",
        "cwe": "89",
        "owasp": "A05:2025",
        "asset": "securecommerce-api",
        "endpoint": "/api/products",
        "parameter": "search",
        "impact": (
            "An attacker may manipulate database queries."
        ),
        "remediation": (
            "Use parameterized database queries."
        ),
        "security_requirement": "SF-INPUT-001",
    }

    finding.update(
        overrides
    )

    return finding


def test_integration_has_expected_identity() -> None:
    """Verify the generic SAST integration identity."""
    integration = GenericSASTIntegration()

    assert integration.name == "sast"
    assert integration.integration_name == "sast"
    assert (
        integration.display_name
        == "Generic Static Application Security Testing"
    )


def test_build_command_uses_source_path() -> None:
    """Verify default command construction."""
    integration = GenericSASTIntegration()

    command = integration.build_command(
        build_configuration()
    )

    assert command == [
        "sast-scanner",
        "--source",
        "src",
        "--format",
        "json",
    ]


def test_build_command_uses_configured_tool_command() -> None:
    """Verify configured tool commands override defaults."""
    integration = GenericSASTIntegration()

    configuration = build_configuration(
        tools=[
            ToolConfiguration(
                name="sast",
                command=[
                    "semgrep",
                    "--config",
                    "auto",
                ],
                arguments=[
                    "--json",
                ],
            )
        ]
    )

    command = integration.build_command(
        configuration
    )

    assert command == [
        "semgrep",
        "--config",
        "auto",
        "--json",
    ]


def test_build_command_uses_configured_executable() -> None:
    """Verify executable-based configuration is supported."""
    integration = GenericSASTIntegration()

    configuration = build_configuration(
        tools=[
            ToolConfiguration(
                name="sast",
                executable="semgrep",
                arguments=[
                    "--json",
                ],
            )
        ]
    )

    command = integration.build_command(
        configuration
    )

    assert command == [
        "semgrep",
        "--json",
    ]


def test_build_command_requires_source_path() -> None:
    """Verify SAST rejects configurations without source."""
    integration = GenericSASTIntegration()

    configuration = build_configuration(
        source_path=None
    )

    with pytest.raises(
        IntegrationConfigurationError,
        match="source_path",
    ):
        integration.build_command(
            configuration
        )


def test_normalize_json_object_with_findings() -> None:
    """Verify standard JSON finding output is normalized."""
    integration = GenericSASTIntegration()

    evidence = build_evidence(
        {
            "findings": [
                build_finding()
            ]
        }
    )

    result = integration.normalize(
        evidence
    )

    assert result.success is True
    assert result.source == "sast"
    assert len(result.findings) == 1


def test_normalize_json_results_alias() -> None:
    """Verify scanners using a results field are supported."""
    integration = GenericSASTIntegration()

    evidence = build_evidence(
        {
            "results": [
                build_finding()
            ]
        }
    )

    result = integration.normalize(
        evidence
    )

    assert len(result.findings) == 1


def test_normalize_json_issues_alias() -> None:
    """Verify scanners using an issues field are supported."""
    integration = GenericSASTIntegration()

    evidence = build_evidence(
        {
            "issues": [
                build_finding()
            ]
        }
    )

    result = integration.normalize(
        evidence
    )

    assert len(result.findings) == 1


def test_normalize_json_string() -> None:
    """Verify JSON stored as scanner stdout is parsed."""
    integration = GenericSASTIntegration()

    payload = json.dumps(
        {
            "findings": [
                build_finding()
            ]
        }
    )

    evidence = build_evidence(
        payload
    )

    result = integration.normalize(
        evidence
    )

    assert result.success is True
    assert len(result.findings) == 1


def test_normalize_stdout_inside_tool_output() -> None:
    """Verify tool execution-shaped evidence is supported."""
    integration = GenericSASTIntegration()

    payload = json.dumps(
        {
            "findings": [
                build_finding()
            ]
        }
    )

    evidence = build_evidence(
        {
            "tool_name": "sast",
            "stdout": payload,
            "exit_code": 0,
        }
    )

    result = integration.normalize(
        evidence
    )

    assert len(result.findings) == 1


def test_normalize_list_payload() -> None:
    """Verify a top-level finding list is supported."""
    integration = GenericSASTIntegration()

    evidence = build_evidence(
        [
            build_finding()
        ]
    )

    result = integration.normalize(
        evidence
    )

    assert len(result.findings) == 1


def test_normalize_finding_fields() -> None:
    """Verify core fields map correctly."""
    integration = GenericSASTIntegration()

    result = integration.normalize(
        build_evidence(
            {
                "findings": [
                    build_finding()
                ]
            }
        )
    )

    finding = result.findings[0]

    assert finding["title"] == "SQL Injection"
    assert finding["source"] == "sast"
    assert finding["source_finding_id"] == "RULE-001"
    assert finding["application"] == "SecureCommerce"
    assert finding["asset"] == "securecommerce-api"
    assert finding["endpoint"] == "/api/products"
    assert finding["parameter"] == "search"
    assert finding["cwe"] == "CWE-89"
    assert finding["owasp"] == "A05:2025"
    assert finding["security_requirement"] == "SF-INPUT-001"
    assert finding["severity"] == "high"
    assert finding["confidence"] == "high"


@pytest.mark.parametrize(
    ("scanner_severity", "expected"),
    [
        ("critical", "critical"),
        ("blocker", "critical"),
        ("high", "high"),
        ("error", "high"),
        ("medium", "medium"),
        ("warning", "medium"),
        ("low", "low"),
        ("info", "info"),
        ("informational", "info"),
    ],
)
def test_normalize_severity(
    scanner_severity: str,
    expected: str,
) -> None:
    """Verify common scanner severity values normalize correctly."""
    integration = GenericSASTIntegration()

    result = integration.normalize(
        build_evidence(
            {
                "findings": [
                    build_finding(
                        severity=scanner_severity
                    )
                ]
            }
        )
    )

    assert result.findings[0]["severity"] == expected


def test_unsupported_severity_becomes_warning() -> None:
    """Verify unsupported severities do not crash the complete parse."""
    integration = GenericSASTIntegration()

    result = integration.normalize(
        build_evidence(
            {
                "findings": [
                    build_finding(
                        severity="unknown-severity"
                    )
                ]
            }
        )
    )

    assert result.success is True
    assert result.findings == []
    assert len(result.warnings) == 1
    assert "Unsupported SAST severity" in result.warnings[0]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("89", "CWE-89"),
        ("CWE-89", "CWE-89"),
        ("cwe-89", "CWE-89"),
        (89, "CWE-89"),
    ],
)
def test_cwe_normalization(
    value,
    expected: str,
) -> None:
    """Verify CWE values are normalized."""
    integration = GenericSASTIntegration()

    result = integration.normalize(
        build_evidence(
            {
                "findings": [
                    build_finding(
                        cwe=value
                    )
                ]
            }
        )
    )

    assert result.findings[0]["cwe"] == expected


def test_cwe_list_uses_first_value() -> None:
    """Verify list-based CWE output is supported."""
    integration = GenericSASTIntegration()

    result = integration.normalize(
        build_evidence(
            {
                "findings": [
                    build_finding(
                        cwe=[
                            "CWE-89",
                            "CWE-564",
                        ]
                    )
                ]
            }
        )
    )

    assert result.findings[0]["cwe"] == "CWE-89"


def test_owasp_list_uses_first_value() -> None:
    """Verify list-based OWASP mappings are supported."""
    integration = GenericSASTIntegration()

    result = integration.normalize(
        build_evidence(
            {
                "findings": [
                    build_finding(
                        owasp=[
                            "A05:2025",
                            "A03:2025",
                        ]
                    )
                ]
            }
        )
    )

    assert result.findings[0]["owasp"] == "A05:2025"


def test_default_description_uses_message() -> None:
    """Verify message is used when description is absent."""
    integration = GenericSASTIntegration()

    finding = build_finding(
        description=None,
        message="Dangerous SQL construction detected.",
    )

    result = integration.normalize(
        build_evidence(
            {
                "findings": [
                    finding
                ]
            }
        )
    )

    assert (
        result.findings[0]["description"]
        == "Dangerous SQL construction detected."
    )


def test_default_description_uses_title() -> None:
    """Verify title becomes the final description fallback."""
    integration = GenericSASTIntegration()

    finding = build_finding(
        description=None,
        message=None,
    )

    result = integration.normalize(
        build_evidence(
            {
                "findings": [
                    finding
                ]
            }
        )
    )

    assert result.findings[0]["description"] == "SQL Injection"


def test_default_remediation_is_provided() -> None:
    """Verify a remediation is always available."""
    integration = GenericSASTIntegration()

    result = integration.normalize(
        build_evidence(
            {
                "findings": [
                    build_finding(
                        remediation=None,
                        recommendation=None,
                    )
                ]
            }
        )
    )

    assert result.findings[0]["remediation"]


def test_default_impact_is_provided() -> None:
    """Verify an impact is always available."""
    integration = GenericSASTIntegration()

    result = integration.normalize(
        build_evidence(
            {
                "findings": [
                    build_finding(
                        impact=None
                    )
                ]
            }
        )
    )

    assert result.findings[0]["impact"]


def test_location_object_is_supported() -> None:
    """Verify nested source location data is extracted."""
    integration = GenericSASTIntegration()

    result = integration.normalize(
        build_evidence(
            {
                "findings": [
                    build_finding(
                        location={
                            "file": "app/routes.py",
                            "line": 42,
                            "column": 10,
                            "endpoint": "/api/products",
                            "parameter": "search",
                        },
                        endpoint=None,
                        parameter=None,
                    )
                ]
            }
        )
    )

    finding = result.findings[0]

    assert finding["endpoint"] == "/api/products"
    assert finding["parameter"] == "search"
    assert (
        finding["metadata"]["source_location"]["file"]
        == "app/routes.py"
    )
    assert (
        finding["metadata"]["source_location"]["line"]
        == "42"
    )
    assert (
        finding["metadata"]["source_location"]["column"]
        == "10"
    )


def test_path_can_be_used_as_endpoint() -> None:
    """Verify path is accepted as an endpoint fallback."""
    integration = GenericSASTIntegration()

    result = integration.normalize(
        build_evidence(
            {
                "findings": [
                    build_finding(
                        endpoint=None,
                        location=None,
                        path="/api/users",
                    )
                ]
            }
        )
    )

    assert result.findings[0]["endpoint"] == "/api/users"


def test_missing_title_produces_warning() -> None:
    """Verify malformed findings are skipped with a warning."""
    integration = GenericSASTIntegration()

    result = integration.normalize(
        build_evidence(
            {
                "findings": [
                    build_finding(
                        title=None,
                        name=None,
                        message=None,
                    )
                ]
            }
        )
    )

    assert result.success is True
    assert result.findings == []
    assert len(result.warnings) == 1
    assert "missing required field 'title'" in (
        result.warnings[0]
    )


def test_findings_field_must_be_list() -> None:
    """Verify malformed findings containers are rejected."""
    integration = GenericSASTIntegration()

    with pytest.raises(
        IntegrationParseError,
        match="must be a list",
    ):
        integration.normalize(
            build_evidence(
                {
                    "findings": {
                        "id": "RULE-001"
                    }
                }
            )
        )


def test_finding_items_must_be_objects() -> None:
    """Verify finding records must be dictionaries."""
    integration = GenericSASTIntegration()

    with pytest.raises(
        IntegrationParseError,
        match="must be an object",
    ):
        integration.normalize(
            build_evidence(
                {
                    "findings": [
                        "invalid-finding"
                    ]
                }
            )
        )


def test_invalid_json_is_rejected() -> None:
    """Verify invalid scanner JSON is rejected."""
    integration = GenericSASTIntegration()

    with pytest.raises(
        IntegrationParseError,
        match="not valid JSON",
    ):
        integration.normalize(
            build_evidence(
                "{invalid-json"
            )
        )


def test_unsupported_output_type_is_rejected() -> None:
    """Verify unsupported raw output types are rejected."""
    integration = GenericSASTIntegration()

    with pytest.raises(
        IntegrationParseError,
        match="Unsupported SAST output format",
    ):
        integration.normalize(
            build_evidence(
                12345
            )
        )


def test_empty_findings_produce_successful_result() -> None:
    """Verify clean SAST output is represented correctly."""
    integration = GenericSASTIntegration()

    result = integration.normalize(
        build_evidence(
            {
                "findings": []
            }
        )
    )

    assert result.success is True
    assert result.findings == []
    assert result.warnings == []


def test_application_defaults_to_unknown_when_missing() -> None:
    """Verify normalization remains valid without application metadata."""
    integration = GenericSASTIntegration()

    evidence = RawEvidence(
        source="sast",
        raw_data={
            "findings": [
                build_finding()
            ]
        },
    )

    result = integration.normalize(
        evidence
    )

    assert result.findings[0]["application"] == "unknown"


def test_asset_defaults_to_evidence_target() -> None:
    """Verify evidence target becomes the asset fallback."""
    integration = GenericSASTIntegration()

    finding = build_finding(
        asset=None
    )

    result = integration.normalize(
        build_evidence(
            {
                "findings": [
                    finding
                ]
            },
            target="src",
        )
    )

    assert result.findings[0]["asset"] == "src"


def test_source_finding_id_uses_rule_id() -> None:
    """Verify rule ID is used as the source identifier."""
    integration = GenericSASTIntegration()

    result = integration.normalize(
        build_evidence(
            {
                "findings": [
                    build_finding(
                        id=None,
                        rule_id="PY-SQL-001",
                    )
                ]
            }
        )
    )

    assert (
        result.findings[0]["source_finding_id"]
        == "PY-SQL-001"
    )


def test_source_finding_id_uses_fingerprint() -> None:
    """Verify fingerprint is used as the final identifier fallback."""
    integration = GenericSASTIntegration()

    result = integration.normalize(
        build_evidence(
            {
                "findings": [
                    build_finding(
                        id=None,
                        rule_id=None,
                        fingerprint="abc123",
                    )
                ]
            }
        )
    )

    assert (
        result.findings[0]["source_finding_id"]
        == "abc123"
    )


def test_source_finding_id_has_deterministic_fallback() -> None:
    """Verify missing scanner IDs receive deterministic indexes."""
    integration = GenericSASTIntegration()

    findings = [
        build_finding(
            id=None,
            rule_id=None,
            fingerprint=None,
        ),
        build_finding(
            id=None,
            rule_id=None,
            fingerprint=None,
        ),
    ]

    result = integration.normalize(
        build_evidence(
            {
                "findings": findings
            }
        )
    )

    assert [
        finding["source_finding_id"]
        for finding in result.findings
    ] == [
        "sast-1",
        "sast-2",
    ]


def test_normalized_output_can_be_used_by_finding_factory() -> None:
    """Verify SAST output is compatible with canonical Finding creation."""
    from secureforge.core.findings import FindingFactory

    integration = GenericSASTIntegration()

    result = integration.normalize(
        build_evidence(
            {
                "findings": [
                    build_finding()
                ]
            }
        )
    )

    findings = FindingFactory().create_many(
        result.findings
    )

    assert len(findings) == 1
    assert findings[0].source == "sast"
    assert findings[0].severity.value == "high"
    assert findings[0].cwe == "CWE-89"
    assert findings[0].security_requirement == "SF-INPUT-001"
