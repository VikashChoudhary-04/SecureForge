"""Tests for the generic API security integration."""

from __future__ import annotations

from secureforge.core.config import (
ScanConfiguration,
TargetConfiguration,
)
from secureforge.core.normalization import RawEvidence
from secureforge.integrations.api import (
GenericAPIIntegration,
)

def make_configuration(
*,
openapi_url: str | None = "http://localhost:3000/openapi.json",
api_base_url: str | None = "http://localhost:3000/api",
base_url: str | None = "http://localhost:3000",
) -> ScanConfiguration:
"""Create an API-security scan configuration."""
return ScanConfiguration(
application="SecureCommerce",
target=TargetConfiguration(
name="securecommerce-api",
openapi_url=openapi_url,
api_base_url=api_base_url,
base_url=base_url,
),
)

def make_evidence(
raw_data: dict,
*,
target: str = "http://localhost:3000/api",
) -> RawEvidence:
"""Create API scanner evidence."""
return RawEvidence(
source="api",
target=target,
raw_data=raw_data,
metadata={
"application": "SecureCommerce",
},
)

def test_build_command_prefers_openapi_url() -> None:
integration = GenericAPIIntegration(
executable="api-scanner"
)


command = integration.build_command(
    make_configuration()
)

assert command == [
    "api-scanner",
    "--openapi",
    "http://localhost:3000/openapi.json",
    "--format",
    "json",
]


def test_build_command_uses_api_base_when_openapi_is_missing() -> None:
integration = GenericAPIIntegration(
executable="api-scanner"
)


command = integration.build_command(
    make_configuration(
        openapi_url=None
    )
)

assert command == [
    "api-scanner",
    "--target",
    "http://localhost:3000/api",
    "--format",
    "json",
]


def test_build_command_supports_custom_template() -> None:
integration = GenericAPIIntegration(
command=[
"custom-api-scanner",
"--spec",
"{openapi}",
"--base",
"{api_base}",
"--target",
"{target}",
]
)


command = integration.build_command(
    make_configuration()
)

assert command == [
    "custom-api-scanner",
    "--spec",
    "http://localhost:3000/openapi.json",
    "--base",
    "http://localhost:3000/api",
    "--target",
    "http://localhost:3000/api",
]


def test_build_command_requires_api_target() -> None:
integration = GenericAPIIntegration()


configuration = make_configuration(
    openapi_url=None,
    api_base_url=None,
    base_url=None,
)

try:
    integration.build_command(
        configuration
    )
except Exception as exc:
    assert "API security scanning" in str(exc)
else:
    raise AssertionError(
        "Expected API target validation to fail."
    )


def test_normalize_bola_finding() -> None:
integration = GenericAPIIntegration()


evidence = make_evidence(
    {
        "findings": [
            {
                "id": "api-001",
                "title": "BOLA",
                "type": "BOLA",
                "severity": "high",
                "confidence": "confirmed",
                "method": "GET",
                "endpoint": "/api/orders/123",
                "parameter": "order_id",
                "cwe": "639",
                "owasp": "API1:2023",
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

assert finding["source_finding_id"] == "api-001"
assert finding["severity"] == "high"
assert finding["confidence"] == "confirmed"
assert finding["endpoint"] == (
    "GET /api/orders/123"
)
assert finding["parameter"] == "order_id"
assert finding["cwe"] == "CWE-639"
assert finding["owasp"] == "API1:2023"
assert finding["security_requirement"] == "SF-AUTHZ-001"


def test_bfla_maps_to_function_authorization_requirement() -> None:
integration = GenericAPIIntegration()


evidence = make_evidence(
    {
        "results": [
            {
                "id": "api-002",
                "name": "Broken Function Level Authorization",
                "type": "BFLA",
                "method": "POST",
                "path": "/api/admin/users",
            }
        ]
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True

finding = result.findings[0]

assert finding["security_requirement"] == "SF-AUTHZ-002"
assert "privileged" in finding["impact"].lower()
assert "function-level authorization" in (
    finding["remediation"].lower()
)


def test_authentication_issue_maps_to_auth_requirement() -> None:
integration = GenericAPIIntegration()


evidence = make_evidence(
    {
        "issues": [
            {
                "id": "api-003",
                "title": "Missing Authentication",
                "type": "authentication",
                "severity": "critical",
            }
        ]
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True

finding = result.findings[0]

assert finding["security_requirement"] == "SF-AUTH-001"
assert "authentication" in (
    finding["impact"].lower()
)


def test_input_validation_issue_maps_to_input_requirement() -> None:
integration = GenericAPIIntegration()


evidence = make_evidence(
    {
        "vulnerabilities": [
            {
                "id": "api-004",
                "title": "SQL Injection",
                "type": "SQL Injection",
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

assert finding["security_requirement"] == "SF-INPUT-001"


def test_custom_security_requirement_is_preserved() -> None:
integration = GenericAPIIntegration()


evidence = make_evidence(
    {
        "findings": [
            {
                "id": "api-005",
                "title": "Custom API Finding",
                "type": "custom",
                "security_requirement": "SF-API-002",
            }
        ]
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True

finding = result.findings[0]

assert finding["security_requirement"] == "SF-API-002"


def test_metadata_preserves_api_context() -> None:
integration = GenericAPIIntegration()


evidence = make_evidence(
    {
        "findings": [
            {
                "id": "api-006",
                "title": "Excessive Data Exposure",
                "type": "excessive data exposure",
                "method": "GET",
                "endpoint": "/api/profile",
                "status_code": 200,
                "operation_id": "getProfile",
                "authentication": "required",
                "response": {
                    "contains": "email"
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

assert finding["metadata"]["method"] == "GET"
assert finding["metadata"]["endpoint"] == "/api/profile"
assert finding["metadata"]["status_code"] == 200
assert finding["metadata"]["operation_id"] == "getProfile"
assert finding["metadata"]["authentication"] == "required"
assert finding["metadata"]["response"]["contains"] == "email"


def test_default_severity_is_medium() -> None:
integration = GenericAPIIntegration()


evidence = make_evidence(
    {
        "findings": [
            {
                "id": "api-007",
                "title": "API Misconfiguration",
            }
        ]
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True
assert result.findings[0]["severity"] == "medium"


def test_stdout_json_is_supported() -> None:
integration = GenericAPIIntegration()


evidence = make_evidence(
    {
        "stdout": (
            '[{"id":"api-008",'
            '"title":"API Security Issue",'
            '"type":"misconfiguration"}]'
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
    == "api-008"
)


def test_invalid_stdout_json_returns_failure() -> None:
integration = GenericAPIIntegration()


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
integration = GenericAPIIntegration()


evidence = make_evidence(
    {
        "findings": [
            "invalid-record",
            {
                "id": "api-009",
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


def test_integration_metadata() -> None:
integration = GenericAPIIntegration(
version="2.1.0"
)


metadata = integration.integration_metadata()

assert metadata["integration"] == "api"
assert metadata["display_name"] == (
    "Generic API Security"
)
assert metadata["version"] == "2.1.0"

