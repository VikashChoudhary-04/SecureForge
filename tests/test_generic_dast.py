"""Tests for the generic DAST integration."""

from **future** import annotations

from secureforge.core.config import (
ScanConfiguration,
TargetConfiguration,
)
from secureforge.core.normalization import RawEvidence
from secureforge.integrations.dast import (
GenericDASTIntegration,
)

def make_configuration(
*,
base_url: str | None = "http://localhost:3000",
) -> ScanConfiguration:
"""Create a DAST scan configuration."""
return ScanConfiguration(
application="SecureCommerce",
target=TargetConfiguration(
name="securecommerce-web",
base_url=base_url,
),
)

def make_evidence(
raw_data: dict,
*,
target: str = "http://localhost:3000",
) -> RawEvidence:
"""Create DAST scanner evidence."""
return RawEvidence(
source="dast",
target=target,
raw_data=raw_data,
metadata={
"application": "SecureCommerce",
},
)

def test_build_command_uses_base_url() -> None:
integration = GenericDASTIntegration(
executable="zap-baseline"
)

```
command = integration.build_command(
    make_configuration()
)

assert command == [
    "zap-baseline",
    "--target",
    "http://localhost:3000",
    "--format",
    "json",
]
```

def test_build_command_supports_custom_template() -> None:
integration = GenericDASTIntegration(
command=[
"custom-dast",
"--url",
"{target}",
"--output",
"results.json",
]
)

```
command = integration.build_command(
    make_configuration()
)

assert command == [
    "custom-dast",
    "--url",
    "http://localhost:3000",
    "--output",
    "results.json",
]
```

def test_build_command_requires_base_url() -> None:
integration = GenericDASTIntegration()

```
configuration = make_configuration(
    base_url=None
)

try:
    integration.build_command(
        configuration
    )
except Exception as exc:
    assert "target.base_url" in str(exc)
else:
    raise AssertionError(
        "Expected base_url validation to fail."
    )
```

def test_normalize_sql_injection_finding() -> None:
integration = GenericDASTIntegration()

```
evidence = make_evidence(
    {
        "findings": [
            {
                "id": "dast-001",
                "title": "SQL Injection",
                "type": "SQL Injection",
                "severity": "high",
                "confidence": "confirmed",
                "method": "GET",
                "url": (
                    "http://localhost:3000/"
                    "api/products"
                ),
                "parameter": "search",
                "cwe": "89",
                "owasp": "A03:2021",
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

assert finding["source_finding_id"] == "dast-001"
assert finding["severity"] == "high"
assert finding["confidence"] == "confirmed"
assert finding["endpoint"] == (
    "GET http://localhost:3000/api/products"
)
assert finding["parameter"] == "search"
assert finding["cwe"] == "CWE-89"
assert finding["owasp"] == "A03:2021"
assert finding["security_requirement"] == "SF-INPUT-001"
```

def test_xss_maps_to_input_requirement() -> None:
integration = GenericDASTIntegration()

```
evidence = make_evidence(
    {
        "results": [
            {
                "id": "dast-002",
                "name": "Reflected XSS",
                "type": "Cross-Site Scripting",
                "url": "/search",
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
```

def test_authentication_issue_maps_to_auth_requirement() -> None:
integration = GenericDASTIntegration()

```
evidence = make_evidence(
    {
        "alerts": [
            {
                "id": "dast-003",
                "name": "Authentication Bypass",
                "type": "auth bypass",
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
```

def test_authorization_issue_maps_to_authz_requirement() -> None:
integration = GenericDASTIntegration()

```
evidence = make_evidence(
    {
        "issues": [
            {
                "id": "dast-004",
                "name": "Broken Access Control",
                "type": "authorization",
            }
        ]
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True

finding = result.findings[0]

assert finding["security_requirement"] == "SF-AUTHZ-001"
```

def test_tls_issue_maps_to_transport_requirement() -> None:
integration = GenericDASTIntegration()

```
evidence = make_evidence(
    {
        "vulnerabilities": [
            {
                "id": "dast-005",
                "name": "Weak TLS Configuration",
                "type": "TLS",
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

assert finding["security_requirement"] == (
    "SF-TRANSPORT-001"
)
```

def test_custom_security_requirement_is_preserved() -> None:
integration = GenericDASTIntegration()

```
evidence = make_evidence(
    {
        "findings": [
            {
                "id": "dast-006",
                "title": "Custom Finding",
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
assert result.findings[0][
    "security_requirement"
] == "SF-API-002"
```

def test_request_response_and_evidence_are_preserved_in_metadata() -> None:
integration = GenericDASTIntegration()

```
evidence = make_evidence(
    {
        "findings": [
            {
                "id": "dast-007",
                "title": "Security Misconfiguration",
                "type": "misconfiguration",
                "request": {
                    "method": "GET",
                    "url": "/admin",
                },
                "response": {
                    "status": 200,
                },
                "evidence": "Sensitive response data",
                "proof": "Confirmed during runtime test",
                "status_code": 200,
            }
        ]
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True

finding = result.findings[0]

assert finding["metadata"]["request"]["method"] == "GET"
assert finding["metadata"]["response"]["status"] == 200
assert finding["metadata"]["evidence"] == (
    "Sensitive response data"
)
assert finding["metadata"]["proof"] == (
    "Confirmed during runtime test"
)
assert finding["metadata"]["status_code"] == 200
```

def test_default_severity_is_medium() -> None:
integration = GenericDASTIntegration()

```
evidence = make_evidence(
    {
        "findings": [
            {
                "id": "dast-008",
                "title": "Web Security Issue",
            }
        ]
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True
assert result.findings[0]["severity"] == "medium"
```

def test_default_confidence_is_unknown() -> None:
integration = GenericDASTIntegration()

```
evidence = make_evidence(
    {
        "findings": [
            {
                "id": "dast-009",
                "title": "Web Security Issue",
            }
        ]
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True
assert result.findings[0]["confidence"] == "unknown"
```

def test_stdout_json_is_supported() -> None:
integration = GenericDASTIntegration()

```
evidence = make_evidence(
    {
        "stdout": (
            '[{"id":"dast-010",'
            '"title":"Missing Security Header",'
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
    == "dast-010"
)
```

def test_invalid_stdout_json_returns_failure() -> None:
integration = GenericDASTIntegration()

```
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
```

def test_malformed_record_becomes_warning() -> None:
integration = GenericDASTIntegration()

```
evidence = make_evidence(
    {
        "findings": [
            "invalid-record",
            {
                "id": "dast-011",
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
```

def test_multiple_dast_findings_are_normalized() -> None:
integration = GenericDASTIntegration()

```
evidence = make_evidence(
    {
        "findings": [
            {
                "id": "dast-012",
                "title": "SQL Injection",
                "type": "SQL Injection",
                "severity": "high",
            },
            {
                "id": "dast-013",
                "title": "Reflected XSS",
                "type": "XSS",
                "severity": "medium",
            },
            {
                "id": "dast-014",
                "title": "Missing TLS",
                "type": "TLS",
                "severity": "low",
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
    "dast-012",
    "dast-013",
    "dast-014",
]
```

def test_integration_metadata() -> None:
integration = GenericDASTIntegration(
version="1.0.0"
)

```
metadata = integration.integration_metadata()

assert metadata["integration"] == "dast"
assert metadata["display_name"] == (
    "Generic Dynamic Application Security Testing"
)
assert metadata["version"] == "1.0.0"
```
