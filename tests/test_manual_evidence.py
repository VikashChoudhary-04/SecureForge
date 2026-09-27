"""Tests for the manual security evidence integration."""

from **future** import annotations

import pytest

from secureforge.integrations.base import (
IntegrationConfigurationError,
IntegrationParseError,
)
from secureforge.integrations.manual import ManualEvidenceIntegration

@pytest.fixture()
def integration() -> ManualEvidenceIntegration:
"""Return a manual evidence integration instance."""
return ManualEvidenceIntegration()

def test_build_command(
integration: ManualEvidenceIntegration,
) -> None:
"""The default command should reference the evidence file."""
command = integration.build_command(
{
"evidence_path": "evidence/burp.json",
}
)

```
assert command == [
    "manual-evidence",
    "--input",
    "evidence/burp.json",
]
```

def test_build_command_custom_string(
integration: ManualEvidenceIntegration,
) -> None:
"""Custom string commands should support evidence-path substitution."""
command = integration.build_command(
{
"evidence_path": "evidence/manual.json",
"manual_command": (
"python importer.py --input {evidence_path}"
),
}
)

```
assert command == [
    "python",
    "importer.py",
    "--input",
    "evidence/manual.json",
]
```

def test_build_command_custom_list(
integration: ManualEvidenceIntegration,
) -> None:
"""Custom list commands should support evidence-path substitution."""
command = integration.build_command(
{
"evidence_path": "evidence/manual.json",
"manual_command": [
"manual-importer",
"--file",
"{evidence_path}",
],
}
)

```
assert command == [
    "manual-importer",
    "--file",
    "evidence/manual.json",
]
```

def test_build_command_requires_evidence_path(
integration: ManualEvidenceIntegration,
) -> None:
"""An evidence path is required."""
with pytest.raises(IntegrationConfigurationError):
integration.build_command({})

def test_validate_config_requires_evidence_path(
integration: ManualEvidenceIntegration,
) -> None:
"""Configuration validation should require an evidence path."""
with pytest.raises(IntegrationConfigurationError):
integration.validate_config({})

def test_supports_target(
integration: ManualEvidenceIntegration,
) -> None:
"""The integration should recognize manual evidence targets."""
assert integration.supports_target(
{"evidence_path": "evidence/burp.json"}
)

```
assert not integration.supports_target({})
```

def test_normalize_burp_finding(
integration: ManualEvidenceIntegration,
) -> None:
"""Burp-validated evidence should normalize correctly."""
output = """
{
"findings": [
{
"finding_id": "BURP-001",
"source": "Burp Suite",
"title": "BOLA in order endpoint",
"severity": "high",
"confidence": "confirmed",
"asset": "securecommerce",
"endpoint": "/api/orders/42",
"parameter": "id",
"cwe": "CWE-639",
"owasp": "API1:2023",
"description": "A user can access another user's order.",
"impact": "Unauthorized access to order data.",
"remediation": "Enforce object-level authorization.",
"evidence": "User A accessed User B order 42.",
"request": "GET /api/orders/42",
"response": "HTTP/1.1 200 OK"
}
]
}
"""

```
findings = integration.normalize(output)

assert len(findings) == 1

finding = findings[0]

assert finding["finding_id"] == "BURP-001"
assert finding["title"] == "BOLA in order endpoint"
assert finding["severity"] == "high"
assert finding["confidence"] == "confirmed"
assert finding["cwe"] == "CWE-639"
assert finding["endpoint"] == "/api/orders/42"
assert finding["parameter"] == "id"
assert finding["security_requirement"] == "SF-AUTHZ-001"
assert finding["metadata"]["validation_source"] == "burp_suite"
assert finding["metadata"]["manual_validation"] is True
assert finding["metadata"]["request"] == "GET /api/orders/42"
assert finding["metadata"]["response"] == "HTTP/1.1 200 OK"
```

def test_normalize_wireshark_evidence(
integration: ManualEvidenceIntegration,
) -> None:
"""Wireshark validation evidence should be preserved."""
output = """
{
"findings": [
{
"source": "Wireshark",
"title": "Credentials transmitted over cleartext HTTP",
"severity": "high",
"packet_reference": "capture.pcapng:packet-144",
"evidence": "HTTP request contained credential fields.",
"description": "Sensitive authentication data was observed in cleartext."
}
]
}
"""

```
findings = integration.normalize(output)

assert len(findings) == 1

finding = findings[0]

assert finding["metadata"]["validation_source"] == "wireshark"
assert finding["metadata"]["packet_reference"] == (
    "capture.pcapng:packet-144"
)
assert finding["security_requirement"] == "SF-AUTH-001"
```

def test_normalize_metasploit_evidence(
integration: ManualEvidenceIntegration,
) -> None:
"""Metasploit validation evidence should be recorded as manual evidence."""
output = """
{
"findings": [
{
"source": "Metasploit",
"title": "Controlled exploit validation",
"severity": "critical",
"confidence": "confirmed",
"description": "A controlled lab exploit succeeded.",
"module": "exploit/example/module",
"command": "run",
"proof_of_concept": "Controlled shell obtained in lab."
}
]
}
"""

```
findings = integration.normalize(output)

assert len(findings) == 1

finding = findings[0]

assert finding["metadata"]["validation_source"] == "metasploit"
assert finding["metadata"]["module"] == (
    "exploit/example/module"
)
assert finding["metadata"]["command"] == "run"
assert finding["evidence"] == (
    "Controlled shell obtained in lab."
)
```

def test_generic_manual_source(
integration: ManualEvidenceIntegration,
) -> None:
"""Unknown sources should remain safe and be marked as other."""
output = """
{
"findings": [
{
"source": "Internal Scanner",
"title": "Test finding",
"severity": "medium",
"description": "Example finding."
}
]
}
"""

```
findings = integration.normalize(output)

assert findings[0]["metadata"]["validation_source"] == "other"
```

def test_default_manual_source(
integration: ManualEvidenceIntegration,
) -> None:
"""Missing source should default to manual."""
output = """
{
"findings": [
{
"title": "Manual authorization finding",
"severity": "medium"
}
]
}
"""

```
findings = integration.normalize(output)

assert findings[0]["metadata"]["validation_source"] == "manual"
```

def test_severity_defaults_to_medium(
integration: ManualEvidenceIntegration,
) -> None:
"""Missing severity should receive a conservative default."""
output = """
{
"findings": [
{
"title": "Unclassified finding"
}
]
}
"""

```
findings = integration.normalize(output)

assert findings[0]["severity"] == "medium"
```

def test_confidence_defaults_to_confirmed(
integration: ManualEvidenceIntegration,
) -> None:
"""Manual evidence is treated as confirmed by default."""
output = """
{
"findings": [
{
"title": "Validated finding"
}
]
}
"""

```
findings = integration.normalize(output)

assert findings[0]["confidence"] == "confirmed"
```

def test_evidence_list_is_combined(
integration: ManualEvidenceIntegration,
) -> None:
"""A list of evidence entries should be preserved as text."""
output = """
{
"findings": [
{
"title": "Evidence list finding",
"evidence": [
"Step 1 succeeded.",
"Step 2 reproduced the issue.",
"Step 3 confirmed impact."
]
}
]
}
"""

```
findings = integration.normalize(output)

assert findings[0]["evidence"] == (
    "Step 1 succeeded.\\n"
    "Step 2 reproduced the issue.\\n"
    "Step 3 confirmed impact."
)
```

def test_requirement_mapping(
integration: ManualEvidenceIntegration,
) -> None:
"""Common manually validated issue types should map to requirements."""
output = """
{
"findings": [
{
"title": "SQL injection confirmed",
"description": "Input parameter is injectable."
},
{
"title": "Authentication bypass",
"description": "Login controls can be bypassed."
},
{
"title": "Exposed API key",
"description": "A secret was discovered."
},
{
"title": "Weak TLS configuration",
"description": "TLS allows insecure configuration."
}
]
}
"""

```
findings = integration.normalize(output)

assert findings[0]["security_requirement"] == "SF-INPUT-001"
assert findings[1]["security_requirement"] == "SF-AUTH-001"
assert findings[2]["security_requirement"] == "SF-SECRET-001"
assert findings[3]["security_requirement"] == "SF-TRANSPORT-001"
```

def test_authz_requirement_mapping(
integration: ManualEvidenceIntegration,
) -> None:
"""Authorization-related manual findings should map to SF-AUTHZ-001."""
output = """
{
"findings": [
{
"title": "IDOR confirmed",
"description": "An authenticated user can access another object."
}
]
}
"""

```
findings = integration.normalize(output)

assert findings[0]["security_requirement"] == "SF-AUTHZ-001"
```

def test_target_asset_is_used(
integration: ManualEvidenceIntegration,
) -> None:
"""The configured target should become the finding asset."""
output = """
{
"findings": [
{
"title": "Manual finding",
"severity": "low"
}
]
}
"""

```
findings = integration.normalize(
    output,
    target={"host": "10.10.10.50"},
)

assert findings[0]["asset"] == "10.10.10.50"
```

def test_empty_output_fails(
integration: ManualEvidenceIntegration,
) -> None:
"""Empty manual evidence should fail clearly."""
with pytest.raises(IntegrationParseError):
integration.normalize("")

def test_invalid_json_fails(
integration: ManualEvidenceIntegration,
) -> None:
"""Invalid JSON should produce a parse error."""
with pytest.raises(IntegrationParseError):
integration.normalize("{invalid-json}")

def test_empty_findings_fail(
integration: ManualEvidenceIntegration,
) -> None:
"""An empty findings collection should fail."""
with pytest.raises(IntegrationParseError):
integration.normalize(
'{"findings": []}'
)

def test_non_dict_entries_are_skipped(
integration: ManualEvidenceIntegration,
) -> None:
"""Malformed individual entries should not crash parsing."""
output = """
[
"invalid",
{
"finding_id": "MANUAL-001",
"title": "Valid finding"
}
]
"""

```
findings = integration.normalize(output)

assert len(findings) == 1
assert findings[0]["finding_id"] == "MANUAL-001"
```

def test_create_evidence(
integration: ManualEvidenceIntegration,
) -> None:
"""Raw manual evidence should preserve source information."""
evidence = integration.create_evidence(
source_reference="evidence/burp.json",
target="securecommerce",
raw_data={
"finding": "BOLA",
},
metadata={
"tool": "Burp Suite Professional",
},
)

```
assert evidence.source == "manual"
assert evidence.source_reference == "evidence/burp.json"
assert evidence.target == "securecommerce"
assert evidence.raw_data["finding"] == "BOLA"
assert evidence.metadata["tool"] == "Burp Suite Professional"
assert evidence.metadata["integration"] == "manual"
```

def test_metadata_is_preserved(
integration: ManualEvidenceIntegration,
) -> None:
"""Custom finding metadata should be retained."""
output = """
{
"findings": [
{
"title": "Metadata finding",
"metadata": {
"tester": "security-team",
"case_id": "CASE-100"
}
}
]
}
"""

```
findings = integration.normalize(output)

assert findings[0]["metadata"]["tester"] == "security-team"
assert findings[0]["metadata"]["case_id"] == "CASE-100"
assert findings[0]["metadata"]["manual_validation"] is True
```
