"""Release-gate models used by SecureForge."""

from **future** import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

def utc_now() -> datetime:
"""Return the current UTC timestamp."""
return datetime.now(timezone.utc)

class ReleaseDecision(str, Enum):
"""Final SecureForge release decision."""

```
PASS = "pass"
REVIEW = "review"
BLOCK = "block"
```

class ReleaseGateInput(BaseModel):
"""Inputs consumed by the release gate."""

```
model_config = ConfigDict(extra="allow")

application: str
version: str
commit_sha: str | None = None

policy_decision: ReleaseDecision

blocking_findings: list[str] = Field(default_factory=list)
review_findings: list[str] = Field(default_factory=list)

failed_regressions: list[str] = Field(default_factory=list)

tool_errors: list[str] = Field(default_factory=list)

exceptions_applied: list[str] = Field(default_factory=list)

metadata: dict[str, Any] = Field(default_factory=dict)
```

class ReleaseDecisionRecord(BaseModel):
"""Complete and traceable release-gate decision."""

```
model_config = ConfigDict(extra="allow")

application: str
version: str
commit_sha: str | None = None

decision: ReleaseDecision

reasons: list[str] = Field(default_factory=list)

blocking_findings: list[str] = Field(default_factory=list)
review_findings: list[str] = Field(default_factory=list)

failed_regressions: list[str] = Field(default_factory=list)
tool_errors: list[str] = Field(default_factory=list)

exceptions_applied: list[str] = Field(default_factory=list)

evaluated_at: datetime = Field(default_factory=utc_now)

metadata: dict[str, Any] = Field(default_factory=dict)

@property
def is_blocked(self) -> bool:
    """Return whether the release is blocked."""
    return self.decision == ReleaseDecision.BLOCK

@property
def requires_review(self) -> bool:
    """Return whether human review is required."""
    return self.decision == ReleaseDecision.REVIEW

@property
def passed(self) -> bool:
    """Return whether the release passed the gate."""
    return self.decision == ReleaseDecision.PASS
```
