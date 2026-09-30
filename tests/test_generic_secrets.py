"""Tests for the generic secret-detection integration."""

from __future__ import annotations

from secureforge.core.config import (
    ScanConfiguration,
    TargetConfiguration,
)
from secureforge.core.normalization import RawEvidence
from secureforge.integrations.secrets import (
    GenericSecretsIntegration,
)


def make_configuration(
    *,
    source_path: str = "./sample-app",
) -> ScanConfiguration:
    """Create a configuration suitable for secret scanning."""
    return ScanConfiguration(
        application="SecureCommerce",
        target=TargetConfiguration(
            name="securecommerce-source",
            source_path=source_path,
        ),
    )


def make_evidence(
    raw_data: dict,
) -> RawEvidence:
    """Create raw secret-scanner evidence."""
    return RawEvidence(
        source="secrets",
        target="./sample-app",
        raw_data=raw_data,
        metadata={
            "application": "SecureCommerce",
        },
    )


def test_build_command_uses_source_path() -> None:
    integration = GenericSecretsIntegration(
        executable="gitleaks"
    )

    command = integration.build_command(
        make_configuration()
    )

    assert command == [
        "gitleaks",
        "--source",
        "./sample-app",
        "--format",
        "json",
    ]


def test_build_command_supports_custom_template() -> None:
    integration = GenericSecretsIntegration(
        command=[
            "custom-secret-scanner",
            "--path",
            "{source}",
            "--json",
        ]
    )

    command = integration.build_command(
        make_configuration(
            source_path="./repository"
        )
    )

    assert command == [
        "custom-secret-scanner",
        "--path",
        "./repository",
        "--json",
    ]


def test_build_command_requires_source_path() -> None:
    integration = GenericSecretsIntegration()

    configuration = make_configuration()
    configuration.target.source_path = None

    try:
        integration.build_command(
            configuration
        )
    except Exception as exc:
        assert "source_path" in str(exc)
    else:
        raise AssertionError(
            "Expected source_path validation to fail."
        )


def test_normalize_secret_finding() -> None:
    integration = GenericSecretsIntegration()

    evidence = make_evidence(
        {
            "findings": [
                {
                    "id": "secret-001",
                    "rule": "AWS Access Key",
                    "severity": "high",
                    "confidence": "high",
                    "file": "config/settings.py",
                    "line": 42,
                    "secret": "AKIA_SUPER_SECRET_VALUE",
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

    assert finding["source_finding_id"] == "secret-001"
    assert finding["title"] == (
        "Potential exposed secret: AWS Access Key"
    )
    assert finding["severity"] == "high"
    assert finding["confidence"] == "high"
    assert finding["security_requirement"] == "SF-SECRET-001"
    assert finding["metadata"]["file"] == (
        "config/settings.py"
    )
    assert finding["metadata"]["line"] == 42


def test_secret_value_is_redacted() -> None:
    integration = GenericSecretsIntegration()

    actual_secret = "AKIA_SUPER_SECRET_VALUE"

    evidence = make_evidence(
        {
            "findings": [
                {
                    "id": "secret-002",
                    "rule": "AWS Access Key",
                    "secret": actual_secret,
                }
            ]
        }
    )

    result = integration.normalize(
        evidence
    )

    assert result.success is True

    finding = result.findings[0]

    assert (
        finding["metadata"]["secret_value"]
        == "[REDACTED]"
    )

    assert actual_secret not in str(
        finding
    )


def test_match_value_is_redacted() -> None:
    integration = GenericSecretsIntegration()

    actual_secret = (
        "ghp_example_token_that_must_not_be_saved"
    )

    evidence = make_evidence(
        {
            "results": [
                {
                    "rule_id": "github-token",
                    "match": actual_secret,
                }
            ]
        }
    )

    result = integration.normalize(
        evidence
    )

    assert result.success is True

    finding = result.findings[0]

    assert (
        finding["metadata"]["secret_value"]
        == "[REDACTED]"
    )
    assert actual_secret not in str(
        finding
    )


def test_redacted_scanner_value_is_preserved() -> None:
    integration = GenericSecretsIntegration()

    evidence = make_evidence(
        {
            "secrets": [
                {
                    "rule": "API Token",
                    "redacted_value": "sk_****7890",
                }
            ]
        }
    )

    result = integration.normalize(
        evidence
    )

    assert result.success is True

    finding = result.findings[0]

    assert (
        finding["metadata"]["secret_value"]
        == "sk_****7890"
    )


def test_default_severity_for_secret_is_high() -> None:
    integration = GenericSecretsIntegration()

    evidence = make_evidence(
        {
            "findings": [
                {
                    "rule": "Database Password"
                }
            ]
        }
    )

    result = integration.normalize(
        evidence
    )

    assert result.success is True
    assert result.findings[0]["severity"] == "high"


def test_cwe_is_normalized() -> None:
    integration = GenericSecretsIntegration()

    evidence = make_evidence(
        {
            "findings": [
                {
                    "rule": "Hardcoded Credential",
                    "cwe": "798",
                }
            ]
        }
    )

    result = integration.normalize(
        evidence
    )

    assert result.success is True
    assert result.findings[0]["cwe"] == "CWE-798"


def test_nested_location_is_supported() -> None:
    integration = GenericSecretsIntegration()

    evidence = make_evidence(
        {
            "findings": [
                {
                    "rule_id": "secret-rule",
                    "location": {
                        "path": "app/config.py",
                        "line_number": 19,
                    },
                }
            ]
        }
    )

    result = integration.normalize(
        evidence
    )

    assert result.success is True

    finding = result.findings[0]

    assert finding["metadata"]["file"] == (
        "app/config.py"
    )
    assert finding["metadata"]["line"] == 19


def test_multiple_secret_findings_are_normalized() -> None:
    integration = GenericSecretsIntegration()

    evidence = make_evidence(
        {
            "findings": [
                {
                    "id": "secret-001",
                    "rule": "API Key",
                },
                {
                    "id": "secret-002",
                    "rule": "Database Password",
                    "severity": "critical",
                },
                {
                    "id": "secret-003",
                    "rule": "Private Key",
                    "severity": "medium",
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
        "secret-001",
        "secret-002",
        "secret-003",
    ]


def test_malformed_record_becomes_warning() -> None:
    integration = GenericSecretsIntegration()

    evidence = make_evidence(
        {
            "findings": [
                "not-an-object",
                {
                    "id": "secret-004",
                    "rule": "API Key",
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


def test_stdout_json_is_supported() -> None:
    integration = GenericSecretsIntegration()

    evidence = make_evidence(
        {
            "stdout": (
                '[{"id":"secret-005",'
                '"rule":"Private Key"}]'
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
        == "secret-005"
    )


def test_invalid_stdout_json_returns_failure() -> None:
    integration = GenericSecretsIntegration()

    evidence = make_evidence(
        {
            "stdout": "this is not json"
        }
    )

    result = integration.normalize(
        evidence
    )

    assert result.success is False
    assert result.errors
    assert "valid JSON" in result.errors[0]


def test_integration_metadata_declares_redaction() -> None:
    integration = GenericSecretsIntegration(
        version="1.0.0"
    )

    metadata = integration.integration_metadata()

    assert metadata["integration"] == "secrets"
    assert metadata["display_name"] == (
        "Generic Secret Detection"
    )
    assert metadata["version"] == "1.0.0"
