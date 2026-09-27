"""Tests for the SecureForge finding model."""

from secureforge.core.findings import (
Confidence,
Evidence,
Finding,
FindingStatus,
Severity,
ValidationStatus,
)

def build_finding() -> Finding:
"""Create a representative finding for testing."""
return Finding(
finding_id="SF-0001",
title="Broken Object Level Authorization",
source="burp",
source_finding_id="BURP-001",
application="SecureCommerce",
asset="securecommerce-api",
endpoint="/api/orders/1002",
parameter="id",
cwe="CWE-639",
owasp="API1",
security_requirement="SF-AUTHZ-001",
severity=Severity.HIGH,
confidence=Confidence.HIGH,
description="A user can access another user's order.",
impact="Unauthorized access to protected order data.",
remediation="Enforce object-level authorization.",
)

def test_finding_is_created_with_expected_defaults() -> None:
"""Verify the finding model initializes correctly."""
finding = build_finding()

```
assert finding.finding_id == "SF-0001"
assert finding.severity == Severity.HIGH
assert finding.status == FindingStatus.OPEN
assert finding.validation_status == ValidationStatus.NOT_VALIDATED
assert finding.evidence == []
```

def test_evidence_can_be_added_to_finding() -> None:
"""Verify evidence is attached and the timestamp is updated."""
finding = build_finding()

```
evidence = Evidence(
    evidence_id="E-0001",
    source="burp",
    source_reference="BURP-001",
    description="User A accessed User B's order.",
    data={
        "status_code": 200,
        "endpoint": "/api/orders/1002",
    },
)

previous_timestamp = finding.last_seen

finding.add_evidence(evidence)

assert len(finding.evidence) == 1
assert finding.evidence[0].evidence_id == "E-0001"
assert finding.last_seen >= previous_timestamp
```

def test_finding_can_be_correlated() -> None:
"""Verify correlated finding IDs are tracked without duplicates."""
finding = build_finding()

```
finding.add_correlation("SF-0002")
finding.add_correlation("SF-0002")
finding.add_correlation("SF-0003")

assert finding.correlated_finding_ids == [
    "SF-0002",
    "SF-0003",
]
```

def test_finding_can_be_validated() -> None:
"""Verify validation changes the finding state."""
finding = build_finding()

```
finding.mark_validated()

assert finding.validation_status == ValidationStatus.CONFIRMED
assert finding.confidence == Confidence.CONFIRMED
```

def test_finding_can_be_rejected() -> None:
"""Verify rejected validation is represented correctly."""
finding = build_finding()

```
finding.mark_rejected()

assert finding.validation_status == ValidationStatus.REJECTED
```

def test_finding_can_be_remediated_and_verified() -> None:
"""Verify remediation and verification lifecycle transitions."""
finding = build_finding()

```
finding.mark_remediated()

assert finding.status == FindingStatus.REMEDIATED

finding.mark_verified()

assert finding.status == FindingStatus.VERIFIED
assert finding.validation_status == ValidationStatus.CONFIRMED
```

def test_verified_finding_can_be_reopened() -> None:
"""Verify regression can reopen a previously verified finding."""
finding = build_finding()

```
finding.mark_verified()
finding.reopen()

assert finding.status == FindingStatus.REOPENED
```
