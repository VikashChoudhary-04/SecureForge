"""Tests for the generic IaC security integration."""

from __future__ import annotations

from secureforge.core.config import (
ScanConfiguration,
TargetConfiguration,
)
from secureforge.core.normalization import RawEvidence
from secureforge.integrations.iac import (
GenericIACIntegration,
)

def make_configuration(
*,
iac_path: str | None = "./terraform",
) -> ScanConfiguration:
"""Create an IaC security scan configuration."""
return ScanConfiguration(
application="SecureCommerce",
target=TargetConfiguration(
name="securecommerce-infrastructure",
iac_path=iac_path,
),
)

def make_evidence(
raw_data: dict,
*,
target: str = "./terraform",
) -> RawEvidence:
"""Create IaC scanner evidence."""
return RawEvidence(
source="iac",
target=target,
raw_data=raw_data,
metadata={
"application": "SecureCommerce",
},
)

def test_build_command_uses_iac_path() -> None:
integration = GenericIACIntegration(
executable="checkov"
)


command = integration.build_command(
    make_configuration()
)

assert command == [
    "checkov",
    "--path",
    "./terraform",
    "--format",
    "json",
]


def test_build_command_supports_custom_template() -> None:
integration = GenericIACIntegration(
command=[
"custom-iac-scanner",
"--directory",
"{path}",
"--source",
"{source}",
"--target",
"{target}",
]
)


command = integration.build_command(
    make_configuration()
)

assert command == [
    "custom-iac-scanner",
    "--directory",
    "./terraform",
    "--source",
    "./terraform",
    "--target",
    "./terraform",
]


def test_build_command_requires_iac_path() -> None:
integration = GenericIACIntegration()


configuration = make_configuration(
    iac_path=None
)

try:
    integration.build_command(
        configuration
    )
except Exception as exc:
    assert "target.iac_path" in str(exc)
else:
    raise AssertionError(
        "Expected IaC path validation to fail."
    )


def test_normalize_public_resource_finding() -> None:
integration = GenericIACIntegration()


evidence = make_evidence(
    {
        "findings": [
            {
                "id": "CKV-AWS-001",
                "title": "Public Security Group",
                "type": "public exposure",
                "severity": "high",
                "confidence": "high",
                "resource": (
                    "aws_security_group.web"
                ),
                "file": "network.tf",
                "line": 24,
                "provider": "aws",
                "service": "ec2",
                "region": "ap-south-1",
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

assert finding["source_finding_id"] == "CKV-AWS-001"
assert finding["severity"] == "high"
assert finding["confidence"] == "high"
assert finding["endpoint"] == "network.tf:24"
assert finding["parameter"] == (
    "aws_security_group.web"
)
assert finding["security_requirement"] == (
    "SF-IAC-001"
)
assert finding["metadata"]["provider"] == "aws"
assert finding["metadata"]["service"] == "ec2"


def test_public_exposure_generates_network_remediation() -> None:
integration = GenericIACIntegration()


evidence = make_evidence(
    {
        "misconfigurations": [
            {
                "id": "iac-001",
                "title": "Public Resource",
                "type": "internet exposed",
            }
        ]
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True

remediation = result.findings[0]["remediation"]

assert "public access" in remediation.lower()
assert "network exposure" in remediation.lower()


def test_permission_issue_generates_least_privilege_remediation() -> None:
integration = GenericIACIntegration()


evidence = make_evidence(
    {
        "issues": [
            {
                "id": "iac-002",
                "title": "Excessive IAM Permissions",
                "type": "excessive permissions",
                "severity": "high",
            }
        ]
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True

finding = result.findings[0]

assert "least-privilege" in (
    finding["remediation"].lower()
)
assert "permissions" in (
    finding["impact"].lower()
)


def test_storage_issue_generates_data_protection_impact() -> None:
integration = GenericIACIntegration()


evidence = make_evidence(
    {
        "checks": [
            {
                "id": "iac-003",
                "title": "Unencrypted Storage",
                "type": "storage encryption",
                "severity": "medium",
            }
        ]
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True

finding = result.findings[0]

assert "sensitive data" in (
    finding["impact"].lower()
)
assert "encryption" in (
    finding["remediation"].lower()
)


def test_custom_security_requirement_is_preserved() -> None:
integration = GenericIACIntegration()


evidence = make_evidence(
    {
        "findings": [
            {
                "id": "iac-004",
                "title": "Custom IaC Finding",
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


def test_resource_metadata_is_preserved() -> None:
integration = GenericIACIntegration()


evidence = make_evidence(
    {
        "findings": [
            {
                "id": "iac-005",
                "title": "Terraform Finding",
                "resource": (
                    "aws_s3_bucket.securecommerce"
                ),
                "resource_type": "aws_s3_bucket",
                "terraform_resource": (
                    "aws_s3_bucket.securecommerce"
                ),
                "project": "securecommerce",
                "account": "123456789",
                "framework": "terraform",
                "references": [
                    "https://example.invalid/control"
                ],
            }
        ]
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True

finding = result.findings[0]

assert finding["metadata"]["resource"] == (
    "aws_s3_bucket.securecommerce"
)
assert finding["metadata"]["resource_type"] == (
    "aws_s3_bucket"
)
assert finding["metadata"]["terraform_resource"] == (
    "aws_s3_bucket.securecommerce"
)
assert finding["metadata"]["project"] == (
    "securecommerce"
)
assert finding["metadata"]["account"] == (
    "123456789"
)
assert finding["metadata"]["framework"] == (
    "terraform"
)


def test_cwe_is_normalized() -> None:
integration = GenericIACIntegration()


evidence = make_evidence(
    {
        "findings": [
            {
                "id": "iac-006",
                "title": "IaC Security Issue",
                "cwe": "732",
            }
        ]
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True
assert result.findings[0]["cwe"] == "CWE-732"


def test_default_severity_is_medium() -> None:
integration = GenericIACIntegration()


evidence = make_evidence(
    {
        "findings": [
            {
                "id": "iac-007",
                "title": "IaC Configuration Issue",
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
integration = GenericIACIntegration()


evidence = make_evidence(
    {
        "findings": [
            {
                "id": "iac-008",
                "title": "IaC Configuration Issue",
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
integration = GenericIACIntegration()


evidence = make_evidence(
    {
        "stdout": (
            '[{"id":"iac-009",'
            '"title":"Public Resource",'
            '"type":"public exposure"}]'
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
    == "iac-009"
)


def test_invalid_stdout_json_returns_failure() -> None:
integration = GenericIACIntegration()


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
integration = GenericIACIntegration()


evidence = make_evidence(
    {
        "findings": [
            "invalid-record",
            {
                "id": "iac-010",
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


def test_multiple_iac_findings_are_normalized() -> None:
integration = GenericIACIntegration()


evidence = make_evidence(
    {
        "findings": [
            {
                "id": "iac-011",
                "title": "Public Resource",
                "type": "public exposure",
            },
            {
                "id": "iac-012",
                "title": "Excessive Permissions",
                "type": "permissions",
            },
            {
                "id": "iac-013",
                "title": "Unencrypted Storage",
                "type": "storage encryption",
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
    "iac-011",
    "iac-012",
    "iac-013",
]


def test_integration_metadata() -> None:
integration = GenericIACIntegration(
version="1.0.0"
)


metadata = integration.integration_metadata()

assert metadata["integration"] == "iac"
assert metadata["display_name"] == (
    "Generic Infrastructure-as-Code Security"
)
assert metadata["version"] == "1.0.0"

