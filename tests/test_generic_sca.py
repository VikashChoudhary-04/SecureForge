"""Tests for the generic SecureForge SCA integration."""

import json

import pytest

from secureforge.core.config import (
ScanConfiguration,
ScanProfile,
TargetConfiguration,
TargetType,
ToolConfiguration,
)
from secureforge.core.findings import FindingFactory
from secureforge.core.normalization import RawEvidence
from secureforge.integrations.base import (
IntegrationConfigurationError,
IntegrationParseError,
)
from secureforge.integrations.sca import (
GenericSCAIntegration,
)

def build_configuration(
*,
source_path: str | None = "src",
tools: list[ToolConfiguration] | None = None,
) -> ScanConfiguration:
"""Create a representative SCA configuration."""
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
"""Create representative SCA evidence."""
return RawEvidence(
source="sca",
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
"""Create a representative SCA vulnerability."""
finding = {
"id": "CVE-2026-0001",
"package": "example-lib",
"installed_version": "1.2.0",
"fixed_version": "1.2.3",
"severity": "high",
"confidence": "high",
"cve": "CVE-2026-0001",
"cwe": "CWE-79",
"cvss": 8.1,
"title": "Cross-Site Scripting in example-lib",
"description": "A vulnerable dependency allows script injection.",
"impact": "An attacker may execute script in an application context.",
"remediation": "Upgrade example-lib to 1.2.3.",
"dependency_type": "runtime",
"security_requirement": "SF-DEP-001",
}

```
finding.update(
    overrides
)

return finding
```

def test_integration_has_expected_identity() -> None:
"""Verify the generic SCA integration identity."""
integration = GenericSCAIntegration()

```
assert integration.name == "sca"
assert integration.integration_name == "sca"
assert (
    integration.display_name
    == "Generic Software Composition Analysis"
)
```

def test_build_command_uses_source_path() -> None:
"""Verify default SCA command construction."""
integration = GenericSCAIntegration()

```
command = integration.build_command(
    build_configuration()
)

assert command == [
    "sca-scanner",
    "--source",
    "src",
    "--format",
    "json",
]
```

def test_build_command_uses_configured_tool_command() -> None:
"""Verify configured SCA command overrides the default."""
integration = GenericSCAIntegration()

```
configuration = build_configuration(
    tools=[
        ToolConfiguration(
            name="sca",
            command=[
                "grype",
                "dir:.",
            ],
            arguments=[
                "-o",
                "json",
            ],
        )
    ]
)

command = integration.build_command(
    configuration
)

assert command == [
    "grype",
    "dir:.",
    "-o",
    "json",
]
```

def test_build_command_uses_configured_executable() -> None:
"""Verify executable-based SCA configuration."""
integration = GenericSCAIntegration()

```
configuration = build_configuration(
    tools=[
        ToolConfiguration(
            name="sca",
            executable="grype",
            arguments=[
                "-o",
                "json",
            ],
        )
    ]
)

command = integration.build_command(
    configuration
)

assert command == [
    "grype",
    "-o",
    "json",
]
```

def test_build_command_requires_source_path() -> None:
"""Verify SCA requires a source path."""
integration = GenericSCAIntegration()

```
configuration = build_configuration(
    source_path=None
)

with pytest.raises(
    IntegrationConfigurationError,
    match="source.path",
):
    integration.build_command(
        configuration
    )
```

def test_normalize_findings_object() -> None:
"""Verify standard SCA findings are normalized."""
integration = GenericSCAIntegration()

```
result = integration.normalize(
    build_evidence(
        {
            "findings": [
                build_finding()
            ]
        }
    )
)

assert result.success is True
assert result.source == "sca"
assert len(result.findings) == 1
```

def test_normalize_vulnerabilities_alias() -> None:
"""Verify vulnerability-based output is supported."""
integration = GenericSCAIntegration()

```
result = integration.normalize(
    build_evidence(
        {
            "vulnerabilities": [
                build_finding()
            ]
        }
    )
)

assert len(result.findings) == 1
```

def test_normalize_results_alias() -> None:
"""Verify results-based output is supported."""
integration = GenericSCAIntegration()

```
result = integration.normalize(
    build_evidence(
        {
            "results": [
                build_finding()
            ]
        }
    )
)

assert len(result.findings) == 1
```

def test_normalize_dependency_alias() -> None:
"""Verify dependency records are supported."""
integration = GenericSCAIntegration()

```
result = integration.normalize(
    build_evidence(
        {
            "dependencies": [
                build_finding()
            ]
        }
    )
)

assert len(result.findings) == 1
```

def test_normalize_json_string() -> None:
"""Verify JSON scanner output stored as text is parsed."""
integration = GenericSCAIntegration()

```
payload = json.dumps(
    {
        "vulnerabilities": [
            build_finding()
        ]
    }
)

result = integration.normalize(
    build_evidence(
        payload
    )
)

assert result.success is True
assert len(result.findings) == 1
```

def test_normalize_stdout_inside_tool_output() -> None:
"""Verify tool execution-shaped evidence is supported."""
integration = GenericSCAIntegration()

```
payload = json.dumps(
    {
        "findings": [
            build_finding()
        ]
    }
)

result = integration.normalize(
    build_evidence(
        {
            "tool_name": "sca",
            "stdout": payload,
            "exit_code": 0,
        }
    )
)

assert len(result.findings) == 1
```

def test_normalize_top_level_list() -> None:
"""Verify a top-level vulnerability list is supported."""
integration = GenericSCAIntegration()

```
result = integration.normalize(
    build_evidence(
        [
            build_finding()
        ]
    )
)

assert len(result.findings) == 1
```

def test_normalize_dependency_fields() -> None:
"""Verify dependency fields map correctly."""
integration = GenericSCAIntegration()

```
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

assert finding["title"] == (
    "Cross-Site Scripting in example-lib"
)
assert finding["source"] == "sca"
assert finding["source_finding_id"] == "CVE-2026-0001"
assert finding["application"] == "SecureCommerce"
assert finding["asset"] == "src"
assert finding["cwe"] == "CWE-79"
assert finding["security_requirement"] == "SF-DEP-001"
assert finding["severity"] == "high"
assert finding["confidence"] == "high"
```

def test_dependency_metadata_is_preserved() -> None:
"""Verify package and version information is retained."""
integration = GenericSCAIntegration()

```
result = integration.normalize(
    build_evidence(
        {
            "findings": [
                build_finding()
            ]
        }
    )
)

metadata = result.findings[0]["metadata"]

assert metadata["package"] == "example-lib"
assert metadata["installed_version"] == "1.2.0"
assert metadata["fixed_version"] == "1.2.3"
assert metadata["vulnerability_id"] == "CVE-2026-0001"
assert metadata["dependency_type"] == "runtime"
assert metadata["cvss"] == 8.1
```

@pytest.mark.parametrize(
("severity", "expected"),
[
("critical", "critical"),
("blocker", "critical"),
("high", "high"),
("error", "high"),
("medium", "medium"),
("moderate", "medium"),
("warning", "medium"),
("low", "low"),
("info", "info"),
("informational", "info"),
],
)
def test_severity_normalization(
severity: str,
expected: str,
) -> None:
"""Verify common SCA severity values normalize correctly."""
integration = GenericSCAIntegration()

```
result = integration.normalize(
    build_evidence(
        {
            "findings": [
                build_finding(
                    severity=severity
                )
            ]
        }
    )
)

assert result.findings[0]["severity"] == expected
```

@pytest.mark.parametrize(
("score", "expected"),
[
(9.8, "critical"),
(9.0, "critical"),
(8.0, "high"),
(7.0, "high"),
(6.9, "medium"),
(4.0, "medium"),
(3.9, "low"),
(0.1, "low"),
(0.0, "info"),
],
)
def test_cvss_score_can_determine_severity(
score: float,
expected: str,
) -> None:
"""Verify CVSS scores map to normalized severity."""
integration = GenericSCAIntegration()

```
finding = build_finding(
    severity=None,
    cvss=score,
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

assert result.findings[0]["severity"] == expected
```

def test_cvss_object_score_is_supported() -> None:
"""Verify structured CVSS data is supported."""
integration = GenericSCAIntegration()

```
finding = build_finding(
    severity=None,
    cvss={
        "score": 9.1,
    },
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

assert result.findings[0]["severity"] == "critical"
assert result.findings[0]["metadata"]["cvss"] == 9.1
```

def test_invalid_cvss_falls_back_to_medium() -> None:
"""Verify invalid CVSS data receives a safe default severity."""
integration = GenericSCAIntegration()

```
finding = build_finding(
    severity=None,
    cvss="not-a-score",
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

assert result.findings[0]["severity"] == "medium"
assert result.findings[0]["metadata"]["cvss"] is None
```

def test_cwe_is_normalized() -> None:
"""Verify CWE values normalize consistently."""
integration = GenericSCAIntegration()

```
result = integration.normalize(
    build_evidence(
        {
            "findings": [
                build_finding(
                    cwe="79"
                )
            ]
        }
    )
)

assert result.findings[0]["cwe"] == "CWE-79"
```

def test_cwe_list_uses_first_value() -> None:
"""Verify list-based CWE output is supported."""
integration = GenericSCAIntegration()

```
result = integration.normalize(
    build_evidence(
        {
            "findings": [
                build_finding(
                    cwe=[
                        "CWE-79",
                        "CWE-89",
                    ]
                )
            ]
        }
    )
)

assert result.findings[0]["cwe"] == "CWE-79"
```

def test_explicit_remediation_is_preferred() -> None:
"""Verify scanner remediation takes precedence."""
integration = GenericSCAIntegration()

```
result = integration.normalize(
    build_evidence(
        {
            "findings": [
                build_finding(
                    remediation="Apply vendor security patch."
                )
            ]
        }
    )
)

assert (
    result.findings[0]["remediation"]
    == "Apply vendor security patch."
)
```

def test_remediation_uses_fixed_version() -> None:
"""Verify fixed-version remediation is generated."""
integration = GenericSCAIntegration()

```
result = integration.normalize(
    build_evidence(
        {
            "findings": [
                build_finding(
                    remediation=None,
                    fixed_version="2.0.0",
                )
            ]
        }
    )
)

assert (
    "2.0.0"
    in result.findings[0]["remediation"]
)
assert "example-lib" in (
    result.findings[0]["remediation"]
)
```

def test_remediation_without_fixed_version_is_still_actionable() -> None:
"""Verify remediation remains useful without a fixed version."""
integration = GenericSCAIntegration()

```
result = integration.normalize(
    build_evidence(
        {
            "findings": [
                build_finding(
                    remediation=None,
                    fixed_version=None,
                )
            ]
        }
    )
)

assert result.findings[0]["remediation"]
assert "example-lib" in (
    result.findings[0]["remediation"]
)
```

def test_missing_package_name_produces_warning() -> None:
"""Verify malformed dependency records are skipped."""
integration = GenericSCAIntegration()

```
result = integration.normalize(
    build_evidence(
        {
            "findings": [
                build_finding(
                    package=None,
                    package_name=None,
                    dependency=None,
                )
            ]
        }
    )
)

assert result.success is True
assert result.findings == []
assert len(result.warnings) == 1
assert "missing a package name" in result.warnings[0]
```

def test_unsupported_severity_produces_warning() -> None:
"""Verify invalid severity does not crash the full parse."""
integration = GenericSCAIntegration()

```
result = integration.normalize(
    build_evidence(
        {
            "findings": [
                build_finding(
                    severity="unknown"
                )
            ]
        }
    )
)

assert result.success is True
assert result.findings == []
assert len(result.warnings) == 1
assert "Unsupported SCA severity" in result.warnings[0]
```

def test_findings_field_must_be_a_list() -> None:
"""Verify malformed finding containers are rejected."""
integration = GenericSCAIntegration()

```
with pytest.raises(
    IntegrationParseError,
    match="must be a list",
):
    integration.normalize(
        build_evidence(
            {
                "findings": {
                    "id": "CVE-2026-0001"
                }
            }
        )
    )
```

def test_finding_items_must_be_objects() -> None:
"""Verify dependency records must be dictionaries."""
integration = GenericSCAIntegration()

```
with pytest.raises(
    IntegrationParseError,
    match="must be an object",
):
    integration.normalize(
        build_evidence(
            {
                "findings": [
                    "invalid"
                ]
            }
        )
    )
```

def test_invalid_json_is_rejected() -> None:
"""Verify invalid scanner JSON is rejected."""
integration = GenericSCAIntegration()

```
with pytest.raises(
    IntegrationParseError,
    match="not valid JSON",
):
    integration.normalize(
        build_evidence(
            "{invalid-json"
        )
    )
```

def test_unsupported_output_type_is_rejected() -> None:
"""Verify unsupported scanner output types are rejected."""
integration = GenericSCAIntegration()

```
with pytest.raises(
    IntegrationParseError,
    match="Unsupported SCA output format",
):
    integration.normalize(
        build_evidence(
            12345
        )
    )
```

def test_empty_vulnerability_list_is_successful() -> None:
"""Verify clean dependency scans are represented correctly."""
integration = GenericSCAIntegration()

```
result = integration.normalize(
    build_evidence(
        {
            "vulnerabilities": []
        }
    )
)

assert result.success is True
assert result.findings == []
assert result.warnings == []
```

def test_application_defaults_to_unknown() -> None:
"""Verify missing application metadata has a safe fallback."""
integration = GenericSCAIntegration()

```
evidence = RawEvidence(
    source="sca",
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
```

def test_asset_uses_evidence_target() -> None:
"""Verify target becomes the dependency asset fallback."""
integration = GenericSCAIntegration()

```
result = integration.normalize(
    build_evidence(
        {
            "findings": [
                build_finding(
                    asset=None
                )
            ]
        },
        target="dependency-lockfile",
    )
)

assert (
    result.findings[0]["asset"]
    == "dependency-lockfile"
)
```

def test_default_asset_is_dependency_collection() -> None:
"""Verify a safe asset fallback exists."""
integration = GenericSCAIntegration()

```
evidence = RawEvidence(
    source="sca",
    raw_data={
        "findings": [
            build_finding(
                asset=None
            )
        ]
    },
    metadata={
        "application": "SecureCommerce",
    },
)

result = integration.normalize(
    evidence
)

assert (
    result.findings[0]["asset"]
    == "dependency-collection"
)
```

def test_vulnerability_id_falls_back_to_ghsa() -> None:
"""Verify GHSA identifiers are supported."""
integration = GenericSCAIntegration()

```
finding = build_finding(
    id=None,
    cve=None,
    ghsa="GHSA-abcd-1234-efgh",
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
    result.findings[0]["source_finding_id"]
    == "GHSA-abcd-1234-efgh"
)
```

def test_vulnerability_id_has_deterministic_fallback() -> None:
"""Verify missing vulnerability IDs receive stable indexes."""
integration = GenericSCAIntegration()

```
findings = [
    build_finding(
        id=None,
        cve=None,
        ghsa=None,
        vulnerability_id=None,
        advisory=None,
    ),
    build_finding(
        id=None,
        cve=None,
        ghsa=None,
        vulnerability_id=None,
        advisory=None,
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
    "sca-1",
    "sca-2",
]
```

def test_default_requirement_is_dependency_security() -> None:
"""Verify dependency findings map to SF-DEP-001 by default."""
integration = GenericSCAIntegration()

```
result = integration.normalize(
    build_evidence(
        {
            "findings": [
                build_finding(
                    security_requirement=None
                )
            ]
        }
    )
)

assert (
    result.findings[0]["security_requirement"]
    == "SF-DEP-001"
)
```

def test_normalized_output_creates_canonical_finding() -> None:
"""Verify SCA output is compatible with FindingFactory."""
integration = GenericSCAIntegration()

```
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
assert findings[0].source == "sca"
assert findings[0].severity.value == "high"
assert findings[0].cwe == "CWE-79"
assert findings[0].security_requirement == "SF-DEP-001"
```

def test_multiple_vulnerabilities_are_preserved() -> None:
"""Verify multiple dependency vulnerabilities are normalized."""
integration = GenericSCAIntegration()

```
findings = [
    build_finding(
        id="CVE-2026-0001",
        package="package-a",
    ),
    build_finding(
        id="CVE-2026-0002",
        package="package-b",
        severity="medium",
    ),
]

result = integration.normalize(
    build_evidence(
        {
            "vulnerabilities": findings
        }
    )
)

assert len(result.findings) == 2
assert result.findings[0]["source_finding_id"] == (
    "CVE-2026-0001"
)
assert result.findings[1]["source_finding_id"] == (
    "CVE-2026-0002"
)
```
