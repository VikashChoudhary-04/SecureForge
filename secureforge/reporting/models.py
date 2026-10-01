"""Reporting models for SecureForge."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ReleaseMetadata(BaseModel):
    """Release information represented in a security report."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str = ""
    application: str
    version: str
    commit_sha: str | None = None
    environment: str
    release_allowed: bool = False
    release_blocked: bool = False


class ScanMetadata(BaseModel):
    """Metadata describing a SecureForge scan."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str
    profile: str
    application: str
    version: str
    commit_sha: str | None = None
    environment: str
    started_at: str
    completed_at: str
    tools: list[str] = Field(default_factory=list)
    tool_errors: list[str] = Field(default_factory=list)


class ReportFinding(BaseModel):
    """Finding representation used by security reports."""

    model_config = ConfigDict(extra="forbid")

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
    first_seen: str
    last_seen: str
    regression_test: str | None = None
    correlation_ids: list[str] = Field(default_factory=list)


class RiskReport(BaseModel):
    """Risk information represented in a security report."""

    model_config = ConfigDict(extra="forbid")

    overall_score: float
    overall_severity: str
    blocked: bool
    factors: list[dict[str, Any]] = Field(default_factory=list)
    evaluated_at: str


class PolicyReport(BaseModel):
    """Policy evaluation represented in a security report."""

    model_config = ConfigDict(extra="forbid")

    allowed: bool
    status: str
    reason: str
    actions: list[dict[str, Any]] = Field(default_factory=list)
    exceptions: list[dict[str, Any]] = Field(default_factory=list)


class RemediationItem(BaseModel):
    """Remediation information for a finding."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    title: str
    status: str
    remediation: str


class RemediationReport(BaseModel):
    """Remediation summary represented in a report."""

    model_config = ConfigDict(extra="forbid")

    total: int
    open_count: int
    remediated_count: int
    findings: list[dict[str, Any]] = Field(default_factory=list)


class RegressionTestReport(BaseModel):
    """Individual regression-test result."""

    model_config = ConfigDict(extra="forbid")

    test_id: str
    status: str
    message: str = ""


class RegressionReport(BaseModel):
    """Regression suite results represented in a report."""

    model_config = ConfigDict(extra="forbid")

    suite_id: str
    suite_name: str = ""
    status: str = ""
    total: int
    passed: int
    failed: int
    errors: int = 0
    errored: int = 0
    skipped: int = 0
    tests: list[RegressionTestReport] = Field(default_factory=list)
    started_at: str | None = None
    completed_at: str | None = None
    duration_seconds: float = 0.0


class RegressionGateReport(BaseModel):
    """Regression-gate decision represented in a report."""

    model_config = ConfigDict(extra="forbid")

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

    model_config = ConfigDict(extra="forbid")

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
    """Validation summary represented in a report."""

    model_config = ConfigDict(extra="forbid")

    total: int
    confirmed: int
    rejected: int
    inconclusive: int
    errors: int
    remediated: int
    all_validated: bool
    results: list[ValidationResultReport] = Field(default_factory=list)


class ValidationGateReport(BaseModel):
    """Validation-gate decision represented in a report."""

    model_config = ConfigDict(extra="forbid")

    allowed: bool
    blocked: bool
    status: str
    reason: str
    confirmed_findings: list[str] = Field(default_factory=list)
    unresolved_findings: list[str] = Field(default_factory=list)
    remediation_verified: list[str] = Field(default_factory=list)
    inconclusive_findings: list[str] = Field(default_factory=list)
    errored_findings: list[str] = Field(default_factory=list)
    requires_attention: bool


class DecisionReport(BaseModel):
    """Final release decision represented in a security report."""

    model_config = ConfigDict(extra="forbid")

    allowed: bool
    blocked: bool
    status: str
    reason: str


class SecurityReport(BaseModel):
    """Complete SecureForge security report."""

    model_config = ConfigDict(extra="forbid")

    release: ReleaseMetadata
    scan: ScanMetadata
    findings: list[ReportFinding] = Field(default_factory=list)
    risk: RiskReport
    policy: PolicyReport
    decision: DecisionReport
    remediation: RemediationReport
    regression: RegressionReport | None = None
    regression_gate: RegressionGateReport | None = None
    validation: ValidationReport | None = None
    validation_results: list[ValidationResultReport] = Field(default_factory=list)
    validation_gate: ValidationGateReport | None = None
    generated_at: str


__all__ = [
    "DecisionReport",
    "RegressionGateReport",
    "RegressionReport",
    "RegressionTestReport",
    "ReleaseMetadata",
    "RemediationItem",
    "RemediationReport",
    "ReportFinding",
    "RiskReport",
    "ScanMetadata",
    "SecurityReport",
    "ValidationGateReport",
    "ValidationReport",
    "ValidationResultReport",
]
