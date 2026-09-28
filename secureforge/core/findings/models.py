"""Core finding models used throughout SecureForge."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

def utc_now() -> datetime:
"""Return the current UTC timestamp."""
return datetime.now(timezone.utc)

class Severity(str, Enum):
"""Normalized finding severity."""

```
CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "info"
```

class Confidence(str, Enum):
"""Confidence level assigned to a finding."""

```
CONFIRMED = "confirmed"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
UNKNOWN = "unknown"
```

class FindingStatus(str, Enum):
"""Lifecycle status of a finding."""

```
OPEN = "open"
IN_PROGRESS = "in_progress"
REMEDIATED = "remediated"
VERIFIED = "verified"
REOPENED = "reopened"
ACCEPTED = "accepted"
```

class ValidationStatus(str, Enum):
"""Validation state of a finding."""

```
NOT_VALIDATED = "not_validated"
PENDING = "pending"
CONFIRMED = "confirmed"
REJECTED = "rejected"
PARTIAL = "partial"
```

class Evidence(BaseModel):
"""Evidence supporting a security finding."""

```
model_config = ConfigDict(extra="allow")

evidence_id: str
source: str
source_reference: str | None = None
description: str
data: dict[str, Any] = Field(default_factory=dict)
collected_at: datetime = Field(default_factory=utc_now)
```

class Finding(BaseModel):
"""Normalized security finding used by SecureForge."""

```
model_config = ConfigDict(extra="allow")

finding_id: str
title: str

source: str
source_finding_id: str | None = None

application: str
asset: str

endpoint: str | None = None
parameter: str | None = None

cwe: str | None = None
owasp: str | None = None
security_requirement: str | None = None

severity: Severity
confidence: Confidence = Confidence.UNKNOWN

description: str
impact: str
remediation: str

evidence: list[Evidence] = Field(default_factory=list)

status: FindingStatus = FindingStatus.OPEN
validation_status: ValidationStatus = ValidationStatus.NOT_VALIDATED

first_seen: datetime = Field(default_factory=utc_now)
last_seen: datetime = Field(default_factory=utc_now)

regression_test: str | None = None

correlated_finding_ids: list[str] = Field(default_factory=list)

metadata: dict[str, Any] = Field(default_factory=dict)

def add_evidence(self, evidence: Evidence) -> None:
    """Add evidence to the finding."""
    self.evidence.append(evidence)
    self.last_seen = utc_now()

def add_correlation(self, finding_id: str) -> None:
    """Record another finding correlated with this finding."""
    if finding_id != self.finding_id and finding_id not in self.correlated_finding_ids:
        self.correlated_finding_ids.append(finding_id)

def mark_validated(self) -> None:
    """Mark the finding as confirmed through validation."""
    self.validation_status = ValidationStatus.CONFIRMED
    self.confidence = Confidence.CONFIRMED
    self.last_seen = utc_now()

def mark_rejected(self) -> None:
    """Mark the finding as rejected during validation."""
    self.validation_status = ValidationStatus.REJECTED
    self.last_seen = utc_now()

def mark_remediated(self) -> None:
    """Mark the finding as remediated."""
    self.status = FindingStatus.REMEDIATED
    self.last_seen = utc_now()

def mark_verified(self) -> None:
    """Mark the finding as verified after remediation."""
    self.status = FindingStatus.VERIFIED
    self.validation_status = ValidationStatus.CONFIRMED
    self.last_seen = utc_now()

def reopen(self) -> None:
    """Reopen a previously remediated or verified finding."""
    self.status = FindingStatus.REOPENED
    self.last_seen = utc_now()
```
