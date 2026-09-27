"""Tests for the SecureForge finding factory."""

import pytest

from secureforge.core.findings import (
Confidence,
Finding,
FindingStatus,
Severity,
ValidationStatus,
)
from secureforge.core.findings.factory import FindingFactory

def build_data() -> dict:
"""Create representative normalized finding data."""
return {
"title": "SQL Injection",
"source": "dast",
"application": "SecureCommerce",
"asset": "securecommerce-api",
"endpoint": "/api/products",
"parameter": "search",
"cwe": "CWE-89",
"owasp": "A03",
"security_requirement": "SF-INPUT-001",
"severity": "high",
"confidence": "confirmed",
"description": "SQL injection was confirmed.",
"impact": "Database queries may be manipulated.",
"remediation": "Use parameterized queries.",
}

def test_factory_creates_finding() -> None:
"""Verify normalized data becomes a Finding."""
finding = FindingFactory().create(
build_data()
)

```
assert isinstance(finding, Finding)
assert finding.title == "SQL Injection"
assert finding.source == "dast"
assert finding.severity == Severity.HIGH
assert finding.confidence == Confidence.CONFIRMED
```

def test_factory_generates_finding_id_when_missing() -> None:
"""Verify a deterministic ID is generated automatically."""
finding = FindingFactory().create(
build_data()
)

```
assert finding.finding_id.startswith("SF-")
assert len(finding.finding_id) == 15
```

def test_factory_preserves_explicit_finding_id() -> None:
"""Verify an existing SecureForge ID is preserved."""
data = build_data()
data["finding_id"] = "SF-EXPLICIT-001"

```
finding = FindingFactory().create(data)

assert finding.finding_id == "SF-EXPLICIT-001"
```

def test_factory_normalizes_case_insensitive_severity() -> None:
"""Verify severity strings are normalized."""
data = build_data()
data["severity"] = "HIGH"

```
finding = FindingFactory().create(data)

assert finding.severity == Severity.HIGH
```

def test_factory_accepts_severity_enum() -> None:
"""Verify Severity enum values are accepted directly."""
data = build_data()
data["severity"] = Severity.CRITICAL

```
finding = FindingFactory().create(data)

assert finding.severity == Severity.CRITICAL
```

def test_factory_normalizes_confidence() -> None:
"""Verify confidence strings are normalized."""
data = build_data()
data["confidence"] = "HIGH"

```
finding = FindingFactory().create(data)

assert finding.confidence == Confidence.HIGH
```

def test_factory_normalizes_status() -> None:
"""Verify lifecycle status strings are normalized."""
data = build_data()
data["status"] = "IN_PROGRESS"

```
finding = FindingFactory().create(data)

assert finding.status == FindingStatus.IN_PROGRESS
```

def test_factory_normalizes_validation_status() -> None:
"""Verify validation status strings are normalized."""
data = build_data()
data["validation_status"] = "CONFIRMED"

```
finding = FindingFactory().create(data)

assert finding.validation_status == ValidationStatus.CONFIRMED
```

def test_factory_applies_model_defaults() -> None:
"""Verify omitted optional lifecycle fields use model defaults."""
finding = FindingFactory().create(
build_data()
)

```
assert finding.status == FindingStatus.OPEN
assert finding.validation_status == (
    ValidationStatus.NOT_VALIDATED
)
```

def test_factory_rejects_non_dictionary_input() -> None:
"""Verify invalid input types are rejected."""
with pytest.raises(
TypeError,
match="must be a dictionary",
):
FindingFactory().create([])

def test_factory_rejects_missing_required_field() -> None:
"""Verify required finding fields are enforced."""
data = build_data()
del data["title"]

```
with pytest.raises(
    ValueError,
    match="Missing required finding fields",
):
    FindingFactory().create(data)
```

def test_factory_rejects_empty_required_field() -> None:
"""Verify empty required values are rejected."""
data = build_data()
data["description"] = "   "

```
with pytest.raises(
    ValueError,
    match="Missing required finding fields",
):
    FindingFactory().create(data)
```

def test_factory_rejects_invalid_severity() -> None:
"""Verify unsupported severity values are rejected."""
data = build_data()
data["severity"] = "extreme"

```
with pytest.raises(
    ValueError,
    match="Invalid finding severity",
):
    FindingFactory().create(data)
```

def test_factory_rejects_invalid_confidence() -> None:
"""Verify unsupported confidence values are rejected."""
data = build_data()
data["confidence"] = "certain"

```
with pytest.raises(
    ValueError,
    match="Invalid finding confidence",
):
    FindingFactory().create(data)
```

def test_factory_rejects_invalid_status() -> None:
"""Verify unsupported lifecycle statuses are rejected."""
data = build_data()
data["status"] = "closed"

```
with pytest.raises(
    ValueError,
    match="Invalid finding status",
):
    FindingFactory().create(data)
```

def test_factory_rejects_invalid_validation_status() -> None:
"""Verify unsupported validation states are rejected."""
data = build_data()
data["validation_status"] = "unknown-state"

```
with pytest.raises(
    ValueError,
    match="Invalid validation status",
):
    FindingFactory().create(data)
```

def test_factory_converts_multiple_findings() -> None:
"""Verify batch finding creation."""
first = build_data()
second = build_data()

```
second["title"] = "Cross Site Scripting"
second["cwe"] = "CWE-79"
second["endpoint"] = "/api/profile"
second["parameter"] = "name"

findings = FindingFactory().create_many(
    [
        first,
        second,
    ]
)

assert len(findings) == 2
assert all(
    isinstance(
        finding,
        Finding,
    )
    for finding in findings
)
assert findings[0].title == "SQL Injection"
assert findings[1].title == "Cross Site Scripting"
assert findings[0].finding_id != findings[1].finding_id
```

def test_factory_preserves_optional_finding_fields() -> None:
"""Verify normalized metadata survives factory conversion."""
data = build_data()
data["metadata"] = {
"scanner_rule": "SQL-001",
"confidence_score": 0.98,
}

```
finding = FindingFactory().create(data)

assert finding.metadata["scanner_rule"] == "SQL-001"
assert finding.metadata["confidence_score"] == 0.98
```

def test_factory_preserves_extra_fields() -> None:
"""Verify Pydantic extra fields remain available."""
data = build_data()
data["scanner_rule_id"] = "DAST-SQL-001"

```
finding = FindingFactory().create(data)

assert finding.scanner_rule_id == "DAST-SQL-001"
```

def test_generated_identifier_is_stable() -> None:
"""Verify equivalent normalized input generates the same ID."""
first = FindingFactory().create(
build_data()
)

```
second = FindingFactory().create(
    build_data()
)

assert first.finding_id == second.finding_id
```

def test_factory_supports_info_severity() -> None:
"""Verify informational findings are supported."""
data = build_data()
data["severity"] = "info"

```
finding = FindingFactory().create(data)

assert finding.severity == Severity.INFO
```

def test_factory_supports_all_valid_severities() -> None:
"""Verify every defined severity can be constructed."""
for severity in Severity:
data = build_data()
data["severity"] = severity.value

```
    finding = FindingFactory().create(data)

    assert finding.severity == severity
```
