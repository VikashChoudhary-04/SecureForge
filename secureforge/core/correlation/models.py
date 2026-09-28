"""Models used by the SecureForge correlation engine."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

class CorrelationType(str, Enum):
"""Relationship between two security findings."""

```
SAME_VULNERABILITY = "same_vulnerability"
SAME_ASSET = "same_asset"
SAME_ENDPOINT = "same_endpoint"
SAME_PARAMETER = "same_parameter"
SUPPORTING_EVIDENCE = "supporting_evidence"
RELATED = "related"
```

class CorrelationConfidence(str, Enum):
"""Confidence that two findings are related."""

```
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
```

class CorrelationLink(BaseModel):
"""Relationship between two findings."""

```
model_config = ConfigDict(extra="allow")

source_finding_id: str
target_finding_id: str

correlation_type: CorrelationType
confidence: CorrelationConfidence

reason: str

signals: list[str] = Field(default_factory=list)

metadata: dict[str, Any] = Field(default_factory=dict)
```

class CorrelatedFinding(BaseModel):
"""A finding assembled from multiple related security observations."""

```
model_config = ConfigDict(extra="allow")

finding_id: str

source_finding_ids: list[str] = Field(default_factory=list)

evidence_ids: list[str] = Field(default_factory=list)

correlation_links: list[CorrelationLink] = Field(default_factory=list)

confidence: CorrelationConfidence = CorrelationConfidence.MEDIUM

metadata: dict[str, Any] = Field(default_factory=dict)

def add_source_finding(self, finding_id: str) -> None:
    """Associate an original finding with the correlated finding."""
    if finding_id not in self.source_finding_ids:
        self.source_finding_ids.append(finding_id)

def add_evidence(self, evidence_id: str) -> None:
    """Associate evidence with the correlated finding."""
    if evidence_id not in self.evidence_ids:
        self.evidence_ids.append(evidence_id)

def add_link(self, link: CorrelationLink) -> None:
    """Add a correlation relationship."""
    self.correlation_links.append(link)

@property
def source_count(self) -> int:
    """Return the number of contributing findings."""
    return len(self.source_finding_ids)

@property
def evidence_count(self) -> int:
    """Return the number of contributing evidence items."""
    return len(self.evidence_ids)
```
