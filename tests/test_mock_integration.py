"""Tests for the SecureForge mock security integration."""

from secureforge.core.config import (
ScanConfiguration,
ScanProfile,
TargetConfiguration,
TargetType,
)
from secureforge.core.normalization import RawEvidence
from secureforge.core.scan import ToolExecutionStatus
from secureforge.integrations.mock import (
MockSecurityIntegration,
)

def build_configuration() -> ScanConfiguration:
"""Create a representative SecureForge configuration."""
return ScanConfiguration(
application="SecureCommerce",
version="1.0.0",
profile=ScanProfile.QUICK,
environment="lab",
target=TargetConfiguration(
name="securecommerce-local",
target_type=TargetType.WEB_AND_API,
base_url="http://localhost:5000",
api_base_url="http://localhost:5000/api",
),
)

def build_finding() -> dict:
"""Create a representative normalized mock finding."""
return {
"title": "SQL Injection",
"source": "mock",
"application": "SecureCommerce",
"asset": "securecommerce-api",
"endpoint": "/api/products",
"parameter": "search",
"cwe": "CWE-89",
"severity": "high",
"description": "Controlled SQL injection finding.",
"impact": "Database queries may be manipulated.",
"remediation": "Use parameterized queries.",
}

def test_mock_integration_has_canonical_name() -> None:
"""Verify the mock integration exposes its canonical name."""
integration = MockSecurityIntegration()

```
assert integration.name == "mock"
assert integration.integration_name == "mock"
assert integration.display_name == "Mock Security Scanner"
```

def test_build_command_contains_application_and_target() -> None:
"""Verify the mock command contains scan context."""
integration = MockSecurityIntegration()

```
command = integration.build_command(
    build_configuration()
)

assert command[0] == "secureforge-mock"
assert "SecureCommerce" in command
assert "securecommerce-local" in command
```

def test_build_command_validates_configuration() -> None:
"""Verify command construction validates scan configuration."""
integration = MockSecurityIntegration()

```
configuration = build_configuration()

command = integration.build_command(
    configuration
)

assert command
```

def test_execute_returns_successful_result() -> None:
"""Verify mock execution returns a successful result."""
integration = MockSecurityIntegration()

```
result = integration.execute(
    build_configuration()
)

assert result.tool_name == "mock"
assert result.integration == "mock"
assert result.status == ToolExecutionStatus.SUCCESS
assert result.exit_code == 0
assert result.error is None
```

def test_execute_is_deterministic() -> None:
"""Verify repeated mock execution produces equivalent results."""
integration = MockSecurityIntegration()

```
first = integration.execute(
    build_configuration()
)

second = integration.execute(
    build_configuration()
)

assert first.tool_name == second.tool_name
assert first.integration == second.integration
assert first.status == second.status
assert first.command == second.command
assert first.stdout == second.stdout
assert first.exit_code == second.exit_code
```

def test_normalize_returns_configured_findings() -> None:
"""Verify mock findings are returned by normalization."""
integration = MockSecurityIntegration(
findings=[
build_finding()
]
)

```
evidence = RawEvidence(
    source="mock",
    target="http://localhost:5000",
    raw_data={
        "test": True
    },
)

result = integration.normalize(
    evidence
)

assert result.success is True
assert result.source == "mock"
assert len(result.findings) == 1
assert result.findings[0]["title"] == "SQL Injection"
```

def test_normalize_preserves_evidence() -> None:
"""Verify normalized results retain source evidence."""
integration = MockSecurityIntegration()

```
evidence = RawEvidence(
    source="mock",
    target="http://localhost:5000",
    raw_data={
        "test": True
    },
)

result = integration.normalize(
    evidence
)

assert len(result.evidence) == 1
assert result.evidence[0] is evidence
```

def test_normalize_rejects_wrong_source() -> None:
"""Verify evidence from another source is rejected."""
integration = MockSecurityIntegration()

```
evidence = RawEvidence(
    source="sast",
    target="http://localhost:5000",
    raw_data={},
)

try:
    integration.normalize(
        evidence
    )
except ValueError as exc:
    assert "Expected evidence source" in str(exc)
else:
    raise AssertionError(
        "Expected ValueError was not raised."
    )
```

def test_add_finding_adds_copy() -> None:
"""Verify findings can be added safely."""
integration = MockSecurityIntegration()

```
finding = build_finding()

integration.add_finding(
    finding
)

assert len(integration.findings) == 1
assert integration.findings[0] == finding
assert integration.findings[0] is not finding
```

def test_add_finding_rejects_non_dictionary() -> None:
"""Verify mock findings must be dictionaries."""
integration = MockSecurityIntegration()

```
try:
    integration.add_finding(
        "not-a-dictionary"
    )
except TypeError as exc:
    assert "must be a dictionary" in str(exc)
else:
    raise AssertionError(
        "Expected TypeError was not raised."
    )
```

def test_clear_findings_removes_all_findings() -> None:
"""Verify configured mock findings can be cleared."""
integration = MockSecurityIntegration(
findings=[
build_finding(),
build_finding(),
]
)

```
integration.clear_findings()

assert integration.findings == []
```

def test_create_evidence_from_execution_uses_target() -> None:
"""Verify execution results become target-aware evidence."""
integration = MockSecurityIntegration()

```
configuration = build_configuration()

result = integration.execute(
    configuration
)

evidence = integration.create_evidence_from_execution(
    result,
    configuration,
)

assert evidence.source == "mock"
assert evidence.target == "http://localhost:5000"
assert evidence.raw_data["exit_code"] == 0
```

def test_create_evidence_uses_integration_metadata() -> None:
"""Verify integration metadata is attached to evidence."""
integration = MockSecurityIntegration(
version="2.0.0",
metadata={
"scanner_type": "test"
},
)

```
result = integration.execute(
    build_configuration()
)

evidence = integration.create_evidence_from_execution(
    result,
    build_configuration(),
)

assert evidence.source_version == "2.0.0"
assert evidence.metadata["integration"] == "mock"
assert evidence.metadata["scanner_type"] == "test"
```

def test_integration_metadata_contains_identity() -> None:
"""Verify integration metadata describes the scanner."""
integration = MockSecurityIntegration(
version="1.2.3"
)

```
metadata = integration.integration_metadata()

assert metadata["integration"] == "mock"
assert metadata["display_name"] == "Mock Security Scanner"
assert metadata["version"] == "1.2.3"
```

def test_mock_integration_can_produce_multiple_findings() -> None:
"""Verify multiple controlled findings are preserved."""
findings = [
build_finding(),
{
**build_finding(),
"title": "Cross-Site Scripting",
"cwe": "CWE-79",
"severity": "medium",
},
]

```
integration = MockSecurityIntegration(
    findings=findings
)

result = integration.normalize(
    RawEvidence(
        source="mock",
        raw_data={},
    )
)

assert len(result.findings) == 2
assert result.findings[0]["cwe"] == "CWE-89"
assert result.findings[1]["cwe"] == "CWE-79"
```

def test_mock_integration_starts_without_findings() -> None:
"""Verify no findings are generated by default."""
integration = MockSecurityIntegration()

```
result = integration.normalize(
    RawEvidence(
        source="mock",
        raw_data={},
    )
)

assert result.success is True
assert result.findings == []
```
