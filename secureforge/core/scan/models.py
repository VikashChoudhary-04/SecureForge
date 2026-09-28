"""Models used by the SecureForge scan orchestration layer."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from secureforge.core.config import ScanProfile
from secureforge.core.findings import Finding
from secureforge.core.policy import PolicyEvaluation
from secureforge.core.release_gate import ReleaseDecisionRecord
from secureforge.core.risk import RiskAssessment


def utc_now() -> datetime:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc)


class ScanStatus(str, Enum):
    """Lifecycle status of a SecureForge scan."""

    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ToolExecutionStatus(str, Enum):
    """Execution status of an individual security integration."""

    NOT_STARTED = "not_started"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"


class ScanConfiguration(BaseModel):
    """Configuration used to start a SecureForge scan."""

    model_config = ConfigDict(extra="allow")

    application: str
    version: str
    profile: ScanProfile = ScanProfile.STANDARD
    environment: str = "development"
    commit_sha: str | None = None
    target: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolExecutionResult(BaseModel):
    """Result produced by one security integration execution."""

    model_config = ConfigDict(extra="allow")

    tool_name: str
    integration: str
    status: ToolExecutionStatus

    command: list[str] = Field(default_factory=list)

    exit_code: int | None = None

    stdout: str = ""
    stderr: str = ""

    duration_seconds: float = Field(
        default=0.0,
        ge=0.0,
    )

    evidence_path: str | None = None
    error: str | None = None

    started_at: datetime | None = None
    completed_at: datetime | None = None

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )

    @property
    def succeeded(self) -> bool:
        """Return whether the tool completed successfully."""
        return self.status == ToolExecutionStatus.SUCCESS

    @property
    def failed(self) -> bool:
        """Return whether the tool execution failed."""
        return self.status in {
            ToolExecutionStatus.FAILED,
            ToolExecutionStatus.TIMEOUT,
        }


class ScanExecution(BaseModel):
    """Execution metadata produced by the scan runner."""

    model_config = ConfigDict(extra="allow")

    scan_id: str
    profile: str
    application: str
    version: str
    commit_sha: str | None = None
    environment: str = "lab"

    started_at: str
    completed_at: str

    status: ScanStatus | str = ScanStatus.COMPLETED

    tools: list[ToolExecutionResult] = Field(
        default_factory=list
    )

    tool_errors: list[str] = Field(
        default_factory=list
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )


class ScanSummary(BaseModel):
    """Summary statistics for a SecureForge scan."""

    model_config = ConfigDict(extra="allow")

    tool_count: int = 0
    successful_tools: int = 0
    failed_tools: int = 0
    skipped_tools: int = 0

    finding_count: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    info_findings: int = 0

    correlated_group_count: int = 0
    regression_failure_count: int = 0

    def update_findings(
        self,
        findings: list[Finding],
    ) -> None:
        """Update severity counters from normalized findings."""
        self.finding_count = len(findings)

        self.critical_findings = sum(
            finding.severity.value == "critical"
            for finding in findings
        )

        self.high_findings = sum(
            finding.severity.value == "high"
            for finding in findings
        )

        self.medium_findings = sum(
            finding.severity.value == "medium"
            for finding in findings
        )

        self.low_findings = sum(
            finding.severity.value == "low"
            for finding in findings
        )

        self.info_findings = sum(
            finding.severity.value == "info"
            for finding in findings
        )


class ScanRun(BaseModel):
    """Complete state and output of a SecureForge verification run."""

    model_config = ConfigDict(extra="allow")

    scan_id: str
    application: str
    version: str
    profile: ScanProfile
    environment: str

    status: ScanStatus = ScanStatus.CREATED

    commit_sha: str | None = None

    started_at: datetime = Field(
        default_factory=utc_now
    )

    completed_at: datetime | None = None

    tool_results: list[ToolExecutionResult] = Field(
        default_factory=list
    )

    findings: list[Finding] = Field(
        default_factory=list
    )

    risk_assessments: list[RiskAssessment] = Field(
        default_factory=list
    )

    policy_evaluation: PolicyEvaluation | None = None

    release_decision: ReleaseDecisionRecord | None = None

    regression_failures: list[str] = Field(
        default_factory=list
    )

    errors: list[str] = Field(
        default_factory=list
    )

    warnings: list[str] = Field(
        default_factory=list
    )

    summary: ScanSummary = Field(
        default_factory=ScanSummary
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )

    def start(self) -> None:
        """Mark the scan as running."""
        self.status = ScanStatus.RUNNING

        if self.started_at is None:
            self.started_at = utc_now()

    def complete(self) -> None:
        """Mark the scan as completed."""
        self.status = ScanStatus.COMPLETED
        self.completed_at = utc_now()

    def fail(
        self,
        error: str,
    ) -> None:
        """Mark the scan as failed and record the error."""
        self.status = ScanStatus.FAILED
        self.completed_at = utc_now()

        if error and error not in self.errors:
            self.errors.append(error)

    def add_tool_result(
        self,
        result: ToolExecutionResult,
    ) -> None:
        """Add an integration execution result."""
        self.tool_results.append(result)

        self.summary.tool_count = len(
            self.tool_results
        )

        self.summary.successful_tools = sum(
            item.succeeded
            for item in self.tool_results
        )

        self.summary.failed_tools = sum(
            item.failed
            for item in self.tool_results
        )

        self.summary.skipped_tools = sum(
            item.status == ToolExecutionStatus.SKIPPED
            for item in self.tool_results
        )

    def add_findings(
        self,
        findings: list[Finding],
    ) -> None:
        """Add normalized findings to the scan."""
        self.findings.extend(findings)

        self.summary.update_findings(
            self.findings
        )

    def add_risk_assessments(
        self,
        assessments: list[RiskAssessment],
    ) -> None:
        """Add contextual risk assessments."""
        self.risk_assessments.extend(
            assessments
        )

    def add_regression_failure(
        self,
        regression_id: str,
    ) -> None:
        """Record a failed security regression."""
        if regression_id not in self.regression_failures:
            self.regression_failures.append(
                regression_id
            )

        self.summary.regression_failure_count = len(
            self.regression_failures
        )

    def add_error(
        self,
        error: str,
    ) -> None:
        """Record a non-fatal scan error."""
        if error and error not in self.errors:
            self.errors.append(error)

    def add_warning(
        self,
        warning: str,
    ) -> None:
        """Record a scan warning."""
        if warning and warning not in self.warnings:
            self.warnings.append(warning)

    @property
    def tool_error_count(self) -> int:
        """Return the number of failed tool executions."""
        return sum(
            result.failed
            for result in self.tool_results
        )

    @property
    def has_findings(self) -> bool:
        """Return whether the scan produced findings."""
        return bool(self.findings)

    @property
    def has_errors(self) -> bool:
        """Return whether the scan contains execution errors."""
        return bool(self.errors)

    @property
    def is_finished(self) -> bool:
        """Return whether the scan reached a terminal state."""
        return self.status in {
            ScanStatus.COMPLETED,
            ScanStatus.FAILED,
        }


class SecurityScanResult(BaseModel):
    """Public result returned by the SecureForge scan orchestrator."""

    model_config = ConfigDict(extra="allow")

    execution: ScanExecution

    findings: list[Finding] = Field(
        default_factory=list
    )

    pipeline: Any | None = None

    scan_id: str | None = None
    application: str | None = None
    version: str | None = None
    profile: str | None = None
    environment: str | None = None

    status: ScanStatus | str = ScanStatus.COMPLETED

    commit_sha: str | None = None

    risk_assessments: list[RiskAssessment] = Field(
        default_factory=list
    )

    policy_evaluation: PolicyEvaluation | None = None

    release_decision: ReleaseDecisionRecord | None = None

    tool_results: list[ToolExecutionResult] = Field(
        default_factory=list
    )

    regression_failures: list[str] = Field(
        default_factory=list
    )

    errors: list[str] = Field(
        default_factory=list
    )

    warnings: list[str] = Field(
        default_factory=list
    )

    summary: ScanSummary = Field(
        default_factory=ScanSummary
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )

    @property
    def passed(self) -> bool:
        """Return whether the scan completed successfully."""
        return self.status == ScanStatus.COMPLETED

    @property
    def has_findings(self) -> bool:
        """Return whether the scan produced findings."""
        return bool(self.findings)

    @property
    def has_errors(self) -> bool:
        """Return whether the scan contains errors."""
        return bool(self.errors)


__all__ = [
    "ScanConfiguration",
    "ScanExecution",
    "ScanProfile",
    "ScanRun",
    "ScanStatus",
    "ScanSummary",
    "SecurityScanResult",
    "ToolExecutionResult",
    "ToolExecutionStatus",
    "utc_now",
]
