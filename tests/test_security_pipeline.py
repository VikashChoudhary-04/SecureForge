"""Tests for the SecureForge security evaluation pipeline."""

from datetime import datetime, timezone

from secureforge.core.config import (
ScanConfiguration,
ScanProfile,
TargetConfiguration,
TargetType,
)
from secureforge.core.findings import (
Finding,
Severity,
)
from secureforge.core.policy import (
PolicyAction,
PolicyConfig,
PolicyRule,
)
from secureforge.core.release_gate import ReleaseDecision
from secureforge.core.risk import (
Environment,
RiskContext,
)
from secureforge.core.scan.models import (
ScanRun,
ScanStatus,
ToolExecutionResult,
ToolExecutionStatus,
)
from secureforge.core.scan.security_pipeline import (
SecurityPipeline,
)

def build_configuration() -> ScanConfiguration:
"""Create a representative scan configuration."""
return ScanConfiguration(
application="SecureCommerce",
version="1.0.0",
profile=ScanProfile.STANDARD,
environment="lab",
target=TargetConfiguration(
name="securecommerce-local",
target_type=TargetType.WEB_AND_API,
base_url="http://localhost:5000",
api_base_url="http://localhost:5000/api",
),
)

def build_scan(
findings: list[Finding] | None = None,
) -> ScanRun:
"""Create a representative completed scan."""
scan = ScanRun(
scan_id="SCAN-TEST001",
application="SecureCommerce",
version="1.0.0",
profile=ScanProfile.STANDARD,
environment="lab",
status=ScanStatus.COMPLETED,
commit_sha="abc123",
)

```
if findings:
    scan.add_findings(
        findings
    )

return scan
```

def build_finding(
finding_id: str,
*,
severity: Severity = Severity.HIGH,
endpoint: str = "/api/orders/1",
parameter: str = "id",
cwe: str = "CWE-639",
security_requirement: str = "SF-AUTHZ-001",
) -> Finding:
"""Create a representative normalized finding."""
timestamp = datetime.now(timezone.utc)

```
return Finding(
    finding_id=finding_id,
    title="BOLA / IDOR",
    source="dast",
    application="SecureCommerce",
    asset="securecommerce-api",
    endpoint=endpoint,
    parameter=parameter,
    cwe=cwe,
    owasp="API1",
    security_requirement=security_requirement,
    severity=severity,
    description="Unauthorized object access was detected.",
    impact="Users may access another user's data.",
    remediation="Enforce object-level authorization.",
    first_seen=timestamp,
    last_seen=timestamp,
)
```

def build_policy(
*,
high_action: PolicyAction = PolicyAction.BLOCK,
medium_action: PolicyAction = PolicyAction.REVIEW,
) -> PolicyConfig:
"""Create a controlled security policy."""
return PolicyConfig(
policy_id="test-policy",
version="1.0",
rules=[
PolicyRule(
rule_id="BLOCK-HIGH",
name="Block High",
description="High findings block releases.",
severity="high",
action=high_action,
),
PolicyRule(
rule_id="REVIEW-MEDIUM",
name="Review Medium",
description="Medium findings require review.",
severity="medium",
action=medium_action,
),
PolicyRule(
rule_id="PASS-LOW",
name="Pass Low",
description="Low findings pass.",
severity="low",
action=PolicyAction.PASS,
),
],
)

def test_pipeline_assesses_risk_for_findings() -> None:
"""Verify every finding receives a risk assessment."""
finding = build_finding(
"SF-001"
)

```
scan = build_scan(
    [finding]
)

pipeline = SecurityPipeline()

evaluated = pipeline.evaluate(
    scan,
    build_configuration(),
    build_policy(),
)

assert len(
    evaluated.risk_assessments
) == 1

assessment = evaluated.risk_assessments[0]

assert assessment.finding_id == "SF-001"
assert assessment.risk_score > 0
```

def test_pipeline_maps_finding_security_requirement_into_risk_context() -> None:
"""Verify finding requirement mapping reaches risk evaluation."""
finding = build_finding(
"SF-002",
security_requirement="SF-AUTHZ-001",
)

```
scan = build_scan(
    [finding]
)

evaluated = SecurityPipeline().evaluate(
    scan,
    build_configuration(),
    build_policy(),
)

assessment = evaluated.risk_assessments[0]

assert (
    assessment.context.security_requirement
    == "SF-AUTHZ-001"
)
```

def test_pipeline_uses_scan_environment_when_context_is_not_provided() -> None:
"""Verify scan environment becomes the default risk context."""
finding = build_finding(
"SF-003"
)

```
scan = build_scan(
    [finding]
)

scan.environment = "production"

evaluated = SecurityPipeline().evaluate(
    scan,
    build_configuration(),
    build_policy(),
)

assessment = evaluated.risk_assessments[0]

assert (
    assessment.context.environment
    == Environment.PRODUCTION
)
```

def test_pipeline_preserves_explicit_risk_context() -> None:
"""Verify caller-provided risk context is preserved."""
finding = build_finding(
"SF-004"
)

```
scan = build_scan(
    [finding]
)

context = RiskContext(
    internet_exposed=True,
    authentication_required=False,
    sensitive_data=True,
    exploit_evidence=True,
    environment=Environment.PRODUCTION,
    security_requirement="SF-AUTHZ-001",
)

evaluated = SecurityPipeline().evaluate(
    scan,
    build_configuration(),
    build_policy(),
    risk_context=context,
)

assessment = evaluated.risk_assessments[0]

assert assessment.context.internet_exposed is True
assert assessment.context.authentication_required is False
assert assessment.context.sensitive_data is True
assert assessment.context.exploit_evidence is True
assert assessment.context.environment == Environment.PRODUCTION
```

def test_pipeline_performs_correlation() -> None:
"""Verify related findings are correlated."""
first = build_finding(
"SF-005",
endpoint="/api/orders/1",
parameter="id",
)

```
second = build_finding(
    "SF-006",
    endpoint="/api/orders/1",
    parameter="id",
)

scan = build_scan(
    [first, second]
)

evaluated = SecurityPipeline().evaluate(
    scan,
    build_configuration(),
    build_policy(),
)

assert (
    evaluated.summary.correlated_group_count
    == 1
)
```

def test_pipeline_stores_policy_evaluation() -> None:
"""Verify policy evaluation is attached to the scan."""
finding = build_finding(
"SF-007",
severity=Severity.HIGH,
)

```
scan = build_scan(
    [finding]
)

evaluated = SecurityPipeline().evaluate(
    scan,
    build_configuration(),
    build_policy(),
)

assert evaluated.policy_evaluation is not None
assert (
    evaluated.policy_evaluation.policy_id
    == "test-policy"
)
```

def test_high_finding_produces_block_policy_decision() -> None:
"""Verify a blocking high-severity finding blocks the policy."""
finding = build_finding(
"SF-008",
severity=Severity.HIGH,
)

```
scan = build_scan(
    [finding]
)

evaluated = SecurityPipeline().evaluate(
    scan,
    build_configuration(),
    build_policy(),
)

assert evaluated.policy_evaluation is not None
assert (
    evaluated.policy_evaluation.decision.value
    == "block"
)

assert "SF-008" in (
    evaluated.policy_evaluation.blocking_findings
)
```

def test_high_finding_produces_block_release_decision() -> None:
"""Verify a blocked policy becomes a release block."""
finding = build_finding(
"SF-009",
severity=Severity.HIGH,
)

```
scan = build_scan(
    [finding]
)

evaluated = SecurityPipeline().evaluate(
    scan,
    build_configuration(),
    build_policy(),
)

assert evaluated.release_decision is not None
assert (
    evaluated.release_decision.decision
    == ReleaseDecision.BLOCK
)
```

def test_medium_finding_requires_review() -> None:
"""Verify a medium finding reaches review."""
finding = build_finding(
"SF-010",
severity=Severity.MEDIUM,
)

```
scan = build_scan(
    [finding]
)

evaluated = SecurityPipeline().evaluate(
    scan,
    build_configuration(),
    build_policy(),
)

assert evaluated.policy_evaluation is not None
assert (
    evaluated.policy_evaluation.decision.value
    == "review"
)

assert evaluated.release_decision is not None
assert (
    evaluated.release_decision.decision
    == ReleaseDecision.REVIEW
)
```

def test_low_finding_can_pass() -> None:
"""Verify a low finding can pass the configured policy."""
finding = build_finding(
"SF-011",
severity=Severity.LOW,
)

```
scan = build_scan(
    [finding]
)

evaluated = SecurityPipeline().evaluate(
    scan,
    build_configuration(),
    build_policy(),
)

assert evaluated.policy_evaluation is not None
assert (
    evaluated.policy_evaluation.decision.value
    == "pass"
)

assert evaluated.release_decision is not None
assert (
    evaluated.release_decision.decision
    == ReleaseDecision.PASS
)
```

def test_empty_scan_can_pass() -> None:
"""Verify a clean scan produces a passing release decision."""
scan = build_scan()

```
evaluated = SecurityPipeline().evaluate(
    scan,
    build_configuration(),
    build_policy(),
)

assert evaluated.policy_evaluation is not None
assert (
    evaluated.policy_evaluation.decision.value
    == "pass"
)

assert evaluated.release_decision is not None
assert (
    evaluated.release_decision.decision
    == ReleaseDecision.PASS
)
```

def test_failed_regression_blocks_release() -> None:
"""Verify failed security regression tests block release."""
scan = build_scan()

```
evaluated = SecurityPipeline().evaluate(
    scan,
    build_configuration(),
    build_policy(),
    failed_regressions=[
        "BOLA-001"
    ],
)

assert (
    "BOLA-001"
    in evaluated.regression_failures
)

assert evaluated.release_decision is not None
assert (
    evaluated.release_decision.decision
    == ReleaseDecision.BLOCK
)
```

def test_failed_tool_is_represented_in_release_evaluation() -> None:
"""Verify tool execution failures reach the release gate."""
scan = build_scan()

```
scan.add_tool_result(
    ToolExecutionResult(
        tool_name="sast",
        integration="sast",
        status=ToolExecutionStatus.FAILED,
        command=["sast"],
        exit_code=1,
        error="SAST execution failed.",
    )
)

evaluated = SecurityPipeline().evaluate(
    scan,
    build_configuration(),
    build_policy(),
)

assert evaluated.release_decision is not None
assert (
    "SAST execution failed."
    in evaluated.release_decision.tool_errors
)
```

def test_pipeline_preserves_commit_sha() -> None:
"""Verify release evaluation preserves the scan commit."""
scan = build_scan()

```
evaluated = SecurityPipeline().evaluate(
    scan,
    build_configuration(),
    build_policy(),
)

assert evaluated.release_decision is not None
assert (
    evaluated.release_decision.commit_sha
    == "abc123"
)
```

def test_pipeline_adds_profile_metadata_to_release_decision() -> None:
"""Verify release records contain useful scan metadata."""
scan = build_scan()

```
evaluated = SecurityPipeline().evaluate(
    scan,
    build_configuration(),
    build_policy(),
)

assert evaluated.release_decision is not None
assert (
    evaluated.release_decision.metadata["profile"]
    == "standard"
)
assert (
    evaluated.release_decision.metadata["environment"]
    == "lab"
)
```

def test_pipeline_records_regression_failure_on_scan() -> None:
"""Verify regression failures update scan statistics."""
scan = build_scan()

```
evaluated = SecurityPipeline().evaluate(
    scan,
    build_configuration(),
    build_policy(),
    failed_regressions=[
        "SQLI-001",
        "XSS-001",
    ],
)

assert evaluated.summary.regression_failure_count == 2
assert evaluated.regression_failures == [
    "SQLI-001",
    "XSS-001",
]
```

def test_pipeline_handles_multiple_findings() -> None:
"""Verify multiple findings receive complete evaluation."""
findings = [
build_finding(
"SF-020",
severity=Severity.HIGH,
),
build_finding(
"SF-021",
severity=Severity.MEDIUM,
endpoint="/api/profile",
parameter="user_id",
),
build_finding(
"SF-022",
severity=Severity.LOW,
endpoint="/api/products",
parameter="search",
),
]

```
scan = build_scan(
    findings
)

evaluated = SecurityPipeline().evaluate(
    scan,
    build_configuration(),
    build_policy(),
)

assert len(
    evaluated.risk_assessments
) == 3

assert evaluated.policy_evaluation is not None
assert (
    evaluated.policy_evaluation.decision.value
    == "block"
)

assert evaluated.release_decision is not None
assert (
    evaluated.release_decision.decision
    == ReleaseDecision.BLOCK
)
```

def test_pipeline_does_not_mutate_finding_count() -> None:
"""Verify evaluation does not alter the finding collection."""
findings = [
build_finding(
"SF-030"
),
build_finding(
"SF-031",
endpoint="/api/profile",
),
]

```
scan = build_scan(
    findings
)

original_count = len(
    scan.findings
)

SecurityPipeline().evaluate(
    scan,
    build_configuration(),
    build_policy(),
)

assert len(
    scan.findings
) == original_count
```

def test_pipeline_can_run_without_findings_or_regressions() -> None:
"""Verify the complete pipeline handles a clean release."""
scan = build_scan()

```
evaluated = SecurityPipeline().evaluate(
    scan,
    build_configuration(),
    build_policy(),
)

assert evaluated.policy_evaluation is not None
assert evaluated.release_decision is not None
assert evaluated.release_decision.passed is True
assert evaluated.risk_assessments == []
```
