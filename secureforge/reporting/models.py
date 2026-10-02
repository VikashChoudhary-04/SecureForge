"""Reporting models for SecureForge."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ReleaseMetadata(BaseModel):
    """Release information represented in a security report."""

    model_config = ConfigDict(extra="allow")

    scan_id: str = ""
    release_id: str = ""
    application: str
    version: str
    commit_sha: str | None = None
    environment: str
    release_allowed: bool = False
    release_blocked: bool = False


class ScanMetadata(BaseModel):
    """Metadata describing a SecureForge scan."""

    model_config = ConfigDict(extra="allow")

    scan_id: str
    profile: str
    application: str = "securecommerce"
    version: str = "1.0.0"
    target: str = ""
    commit_sha: str | None = None
    environment: str = "test"
    started_at: str = ""
    completed_at: str = ""
    status: str = "completed"
    tools: list[str] = Field(default_factory=list)
    tool_errors: list[str] = Field(default_factory=list)
    integrations: list[str] = Field(default_factory=list)


class ReportFinding(BaseModel):
    """Finding representation used by security reports."""

    model_config = ConfigDict(extra="allow")

    finding_id: str
    title: str
    source: str
    asset: str
    application: str
    endpoint: str | None = None
    parameter: str | None = None
    cwe: str | None = None
    owasp_mapping: str | None = None
    security_requirement: str | None = None
    severity: str
    confidence: str
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    description: str
    impact: str
    remediation: str
    status: str
    validation_status: str
    first_seen: str = ""
    last_seen: str = ""
    regression_test: str | None = None
    correlation_ids: list[str] = Field(default_factory=list)
    correlations: list[Any] = Field(default_factory=list)


class RiskReport(BaseModel):
    """Risk information represented in a security report."""

    model_config = ConfigDict(extra="allow")

    score: float
    highest_severity: str
    finding_count: int = 0
    confirmed_critical: int = 0
    confirmed_high: int = 0
    factors: Any = Field(default_factory=list)
    evaluated_at: str = ""

    @property
    def overall_score(self) -> float:
        return self.score

    @property
    def overall_severity(self) -> str:
        return self.highest_severity


class PolicyReport(BaseModel):
    """Policy evaluation represented in a security report."""

    model_config = ConfigDict(extra="allow")

    policy_name: str = "default"
    action: str = ""
    allowed: bool = False
    reason: str = ""
    violations: list[str] = Field(default_factory=list)
    actions: Any = Field(default_factory=list)
    tool_errors: list[str] = Field(default_factory=list)
    regression_failures: list[str] = Field(default_factory=list)
    exceptions: Any = Field(default_factory=list)

    @property
    def status(self) -> str:
        return self.action


class RemediationItem(BaseModel):
    """Remediation information for a finding."""

    model_config = ConfigDict(extra="allow")

    finding_id: str
    title: str
    status: str
    remediation: str


class RemediationReport(BaseModel):
    """Remediation summary represented in a report."""

    model_config = ConfigDict(extra="allow")

    total: int
    open: int = 0
    remediated: int = 0
    verified: int = 0
    in_progress: int = 0
    resolved: int = 0
    items: list[RemediationItem] = Field(default_factory=list)

    @property
    def open_count(self) -> int:
        return self.open

    @property
    def remediated_count(self) -> int:
        return self.remediated


class RegressionTestReport(BaseModel):
    """Individual regression-test result."""

    model_config = ConfigDict(extra="allow")

    test_id: str
    status: str
    message: str = ""


class RegressionReport(BaseModel):
    """Regression suite results represented in a security report."""

    model_config = ConfigDict(extra="allow")

    suite_id: str
    suite_name: str = ""
    status: str = ""
    total: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    errored: int = 0
    skipped: int = 0
    tests: list[RegressionTestReport] = Field(default_factory=list)
    started_at: str | None = None
    completed_at: str | None = None
    duration_seconds: float = 0.0
    tests_total: int = 0
    tests_failed: int = 0


class RegressionGateReport(BaseModel):
    """Regression-gate decision represented in a security report."""

    model_config = ConfigDict(extra="allow")

    allowed: bool
    blocked: bool
    status: str
    reason: str
    failed_tests: list[str] = Field(default_factory=list)
    errored_tests: list[str] = Field(default_factory=list)
    skipped_tests: list[str] = Field(default_factory=list)
    failures: list[str] = Field(default_factory=list)


class ValidationResultReport(BaseModel):
    """Individual validation result represented in a report."""

    model_config = ConfigDict(extra="allow")

    finding_id: str
    outcome: str
    message: str
    validator: str
    validated_at: str
    remediation_verified: bool
    confirmed: bool
    rejected: bool
    inconclusive: bool
    failed: bool
    evidence: list[dict[str, Any]] = Field(default_factory=list)


class ValidationReport(BaseModel):
    """Validation summary represented in a security report."""

    model_config = ConfigDict(extra="allow")

    total: int
    confirmed: int
    rejected: int
    inconclusive: int
    errors: int
    remediated: int
    all_validated: bool
    results: list[ValidationResultReport] = Field(default_factory=list)


class ValidationGateReport(BaseModel):
    """Validation-gate decision represented in a security report."""

    model_config = ConfigDict(extra="allow")

    allowed: bool
    blocked: bool
    status: str
    reason: str
    confirmed_findings: list[str] = Field(default_factory=list)
    unresolved_findings: list[str] = Field(default_factory=list)
    remediation_verified: list[str] = Field(default_factory=list)
    inconclusive_findings: list[str] = Field(default_factory=list)
    errored_findings: list[str] = Field(default_factory=list)
    requires_attention: bool = False


class DecisionReport(BaseModel):
    """Final release decision represented in a security report."""

    model_config = ConfigDict(extra="allow")

    status: str
    reason: str
    release_allowed: bool = False

    @property
    def allowed(self) -> bool:
        return self.release_allowed


class SecurityReport(BaseModel):
    """Complete SecureForge security report."""

    model_config = ConfigDict(extra="allow")

    release: ReleaseMetadata
    scan: ScanMetadata
    findings: list[ReportFinding] = Field(default_factory=list)
    risk: RiskReport
    policy: PolicyReport
    remediation: RemediationReport
    decision: DecisionReport
    regression: RegressionReport | None = None
    regression_gate: RegressionGateReport | None = None
    validation: ValidationReport | None = None
    validation_results: list[ValidationResultReport] = Field(
        default_factory=list
    )
    validation_gate: ValidationGateReport | None = None
    generated_at: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
