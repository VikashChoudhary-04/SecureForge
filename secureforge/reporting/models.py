"""Models used to build SecureForge security reports."""

from **future** import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

def utc_now() -> datetime:
"""Return the current UTC timestamp."""
return datetime.now(timezone.utc)

class ReleaseMetadata(BaseModel):
"""Metadata identifying the release being evaluated."""

```
model_config = ConfigDict(extra="allow")

release_id: str
application: str
version: str
commit_sha: str | None = None
environment: str
profile: str
timestamp: datetime = Field(
    default_factory=utc_now
)
```

class ScanMetadata(BaseModel):
"""Metadata describing the security verification run."""

```
model_config = ConfigDict(extra="allow")

scan_id: str
status: str
started_at: datetime | None = None
completed_at: datetime | None = None
integrations: list[str] = Field(
    default_factory=list
)
```

class ReportFinding(BaseModel):
"""Finding representation included in a security report."""

```
model_config = ConfigDict(extra="allow")

finding_id: str
title: str
source: str
source_finding_ids: list[str] = Field(
    default_factory=list
)

application: str
asset: str

endpoint: str | None = None
parameter: str | None = None

cwe: str | None = None
owasp: str | None = None
security_requirement: str | None = None

severity: str
confidence: str

description: str
impact: str
remediation: str

status: str
validation_status: str

regression_test: str | None = None
evidence_count: int = 0
```

class RiskReport(BaseModel):
"""Risk evaluation included in a security report."""

```
model_config = ConfigDict(extra="allow")

overall_score: float
highest_severity: str
confirmed_critical: int = 0
confirmed_high: int = 0
risk_factors: dict[str, Any] = Field(
    default_factory=dict
)
```

class PolicyReport(BaseModel):
"""Release-policy evaluation included in a report."""

```
model_config = ConfigDict(extra="allow")

policy_name: str
critical_action: str
high_action: str
medium_action: str
low_action: str
info_action: str = "pass"
tool_errors: list[str] = Field(
    default_factory=list
)
regression_failures: list[str] = Field(
    default_factory=list
)
exceptions: list[dict[str, Any]] = Field(
    default_factory=list
)
```

class RemediationReport(BaseModel):
"""Remediation lifecycle summary."""

```
model_config = ConfigDict(extra="allow")

open_findings: int = 0
remediated_findings: int = 0
verified_findings: int = 0
pending_retests: int = 0
```

class RegressionTestReport(BaseModel):
"""Result of one security regression test."""

```
model_config = ConfigDict(extra="allow")

test_id: str
requirement: str
status: str
expected_result: str | None = None
actual_result: str | None = None
message: str | None = None
```

class RegressionReport(BaseModel):
"""Security regression suite summary."""

```
model_config = ConfigDict(extra="allow")

suite: str
tests_total: int = 0
tests_passed: int = 0
tests_failed: int = 0
tests: list[RegressionTestReport] = Field(
    default_factory=list
)
```

class DecisionReport(BaseModel):
"""Final release decision."""

```
model_config = ConfigDict(extra="allow")

status: str
reason: str
release_allowed: bool
```

class SecurityReport(BaseModel):
"""Complete SecureForge security verification report."""

```
model_config = ConfigDict(extra="allow")

release: ReleaseMetadata
scan: ScanMetadata

findings: list[ReportFinding] = Field(
    default_factory=list
)

risk: RiskReport
policy: PolicyReport
remediation: RemediationReport
regression: RegressionReport
decision: DecisionReport

generated_at: datetime = Field(
    default_factory=utc_now
)

metadata: dict[str, Any] = Field(
    default_factory=dict
)
```
