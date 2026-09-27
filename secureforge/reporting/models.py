"""Data models for SecureForge security reporting."""

from **future** import annotations

from typing import Any

from pydantic import BaseModel, Field

class ReleaseMetadata(BaseModel):
"""Metadata describing the release being evaluated."""

```
release_id: str
application: str
version: str
commit_sha: str
environment: str
timestamp: str
```

class ScanMetadata(BaseModel):
"""Metadata describing the security scan."""

```
scan_id: str
profile: str
status: str
tools: list[str] = Field(
    default_factory=list
)
started_at: str
completed_at: str
duration_seconds: float
```

class ReportFinding(BaseModel):
"""Finding representation used in security reports."""

```
finding_id: str
title: str
source: str
asset: str
application: str | None = None
endpoint: str | None = None
parameter: str | None = None
severity: str
confidence: str
status: str
validation_status: str
cwe: str | None = None
owasp_mapping: str | None = None
security_requirement: str | None = None
description: str
impact: str
remediation: str
evidence: list[dict[str, Any]] = Field(
    default_factory=list
)
correlations: list[str] = Field(
    default_factory=list
)
regression_test: str | None = None
```

class RiskReport(BaseModel):
"""Risk assessment section of the report."""

```
score: float
highest_severity: str
confirmed_critical: int
confirmed_high: int
factors: list[Any] = Field(
    default_factory=list
)
```

class PolicyReport(BaseModel):
"""Policy evaluation section of the report."""

```
policy_name: str
actions: list[Any] = Field(
    default_factory=list
)
tool_errors: list[str] = Field(
    default_factory=list
)
regression_failures: list[str] = Field(
    default_factory=list
)
exceptions: list[Any] = Field(
    default_factory=list
)
```

class RemediationReport(BaseModel):
"""Remediation summary section."""

```
total: int
open: int
in_progress: int
resolved: int
verified: int
items: list[Any] = Field(
    default_factory=list
)
```

class RegressionTestReport(BaseModel):
"""Individual regression test result."""

```
test_id: str
status: str
expected: str
actual: str
message: str
evidence: dict[str, Any] = Field(
    default_factory=dict
)
```

class RegressionReport(BaseModel):
"""Regression testing section of the report."""

```
suite_id: str
suite_name: str
status: str
total: int
passed: int
failed: int
errors: int
skipped: int
tests: list[RegressionTestReport] = Field(
    default_factory=list
)
started_at: str | None = None
completed_at: str | None = None
duration_seconds: float = 0.0
```

class RegressionGateReport(BaseModel):
"""Regression-specific release-gate decision."""

```
allowed: bool
blocked: bool
status: str
reason: str
failed_tests: list[str] = Field(
    default_factory=list
)
errored_tests: list[str] = Field(
    default_factory=list
)
skipped_tests: list[str] = Field(
    default_factory=list
)
failures: list[str] = Field(
    default_factory=list
)
```

class DecisionReport(BaseModel):
"""Final release-gate decision."""

```
status: str
reason: str
release_allowed: bool
```

class SecurityReport(BaseModel):
"""Complete SecureForge security report."""

```
release: ReleaseMetadata
scan: ScanMetadata
findings: list[ReportFinding] = Field(
    default_factory=list
)
risk: RiskReport
policy: PolicyReport
remediation: RemediationReport
regression: RegressionReport
regression_gate: RegressionGateReport | None = None
decision: DecisionReport
generated_at: str
```
