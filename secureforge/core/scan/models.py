"""Models used by SecureForge scan orchestration."""
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
    return datetime.now(timezone.utc)


class ScanStatus(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ToolExecutionStatus(str, Enum):
    NOT_STARTED = "not_started"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"


class RawEvidence(BaseModel):
    model_config = ConfigDict(extra="allow")

    source: str
    source_version: str = "unknown"
    source_reference: str | None = None
    target: Any | None = None
    raw_data: Any = None
    collected_at: datetime = Field(default_factory=utc_now)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanConfiguration(BaseModel):
    model_config = ConfigDict(extra="allow")

    application: str
    version: str
    profile: ScanProfile = ScanProfile.STANDARD
    environment: str = "development"
    commit_sha: str | None = None
    target: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolExecutionResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    tool_name: str
    integration: str
    status: ToolExecutionStatus
    command: list[str] = Field(default_factory=list)
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = Field(default=0.0, ge=0.0)
    evidence_path: str | None = None
    error: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def succeeded(self) -> bool:
        return self.status == ToolExecutionStatus.SUCCESS

    @property
    def failed(self) -> bool:
        return self.status in {
            ToolExecutionStatus.FAILED,
            ToolExecutionStatus.TIMEOUT,
        }


class ScanExecution(BaseModel):
    model_config = ConfigDict(extra="allow")

    scan_id: str
    profile: str
    application: str = "securecommerce"
    version: str = "1.0.0"
    commit_sha: str | None = None
    environment: str = "lab"
    target: str | None = None
    started_at: str
    completed_at: str
    status: ScanStatus | str = ScanStatus.COMPLETED
    tools: list[ToolExecutionResult] = Field(default_factory=list)
    tool_errors: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanSummary(BaseModel):
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

    def update_findings(self, findings: list[Finding]) -> None:
        self.finding_count = len(findings)
        self.critical_findings = sum(
            f.severity.value == "critical" for f in findings
        )
        self.high_findings = sum(
            f.severity.value == "high" for f in findings
        )
        self.medium_findings = sum(
            f.severity.value == "medium" for f in findings
        )
        self.low_findings = sum(
            f.severity.value == "low" for f in findings
        )
        self.info_findings = sum(
            f.severity.value in {"info", "informational"}
            for f in findings
        )


class ScanRun(BaseModel):
    model_config = ConfigDict(extra="allow")

    scan_id: str
    application: str
    version: str
    profile: ScanProfile
    environment: str
    status: ScanStatus = ScanStatus.CREATED
    commit_sha: str | None = None
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
    tool_results: list[ToolExecutionResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    risk_assessments: list[RiskAssessment] = Field(default_factory=list)
    policy_evaluation: PolicyEvaluation | None = None
    release_decision: ReleaseDecisionRecord | None = None
    regression_failures: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def start(self) -> None:
        self.status = ScanStatus.RUNNING
        if self.started_at is None:
            self.started_at = utc_now()

    def complete(self) -> None:
        self.status = ScanStatus.COMPLETED
        self.completed_at = utc_now()

    def fail(self, error: str) -> None:
        self.status = ScanStatus.FAILED
        self.completed_at = utc_now()
        self.add_error(error)

    def add_error(self, error: str) -> None:
        if error and error not in self.errors:
            self.errors.append(error)

    def add_warning(self, warning: str) -> None:
        if warning and warning not in self.warnings:
            self.warnings.append(warning)

    def add_tool_result(self, result: ToolExecutionResult) -> None:
        self.tool_results.append(result)
        self.summary.tool_count += 1

        if result.succeeded:
            self.summary.successful_tools += 1
        elif result.status == ToolExecutionStatus.SKIPPED:
            self.summary.skipped_tools += 1
        elif result.failed:
            self.summary.failed_tools += 1

        if result.failed and result.error:
            self.add_error(result.error)

    def add_findings(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)
        self.summary.update_findings(self.findings)

    def add_regression_failure(self, test_id: str) -> None:
        if test_id and test_id not in self.regression_failures:
            self.regression_failures.append(test_id)
        self.summary.regression_failure_count = len(
            self.regression_failures
        )

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def has_errors(self) -> bool:
        return bool(self.errors)

    @property
    def is_finished(self) -> bool:
        return self.status in {
            ScanStatus.COMPLETED,
            ScanStatus.FAILED,
        }

    @property
    def tool_error_count(self) -> int:
        return sum(1 for result in self.tool_results if result.failed)


class SecurityScanResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    execution: ScanExecution
    findings: list[Finding] = Field(default_factory=list)
    pipeline: Any | None = None
    scan_id: str | None = None
    application: str | None = None
    version: str | None = None
    profile: str | None = None
    environment: str | None = None
    status: ScanStatus | str = ScanStatus.COMPLETED
    commit_sha: str | None = None
    risk_assessments: list[RiskAssessment] = Field(default_factory=list)
    policy_evaluation: PolicyEvaluation | None = None
    release_decision: ReleaseDecisionRecord | None = None
    tool_results: list[ToolExecutionResult] = Field(default_factory=list)
    regression_failures: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def target(self) -> str | None:
        return self.execution.target

    @property
    def release_gate(self) -> Any:
        return getattr(
            self.pipeline,
            "release_gate",
            self.release_decision,
        )

    @property
    def release_allowed(self) -> bool:
        return bool(
            getattr(
                self.release_gate,
                "release_allowed",
                getattr(self.release_gate, "allowed", False),
            )
        )

    @property
    def release_blocked(self) -> bool:
        return not self.release_allowed

    @property
    def release_status(self) -> str:
        gate = self.release_gate
        status = getattr(gate, "status", "")
        return getattr(status, "value", status)

    @property
    def passed(self) -> bool:
        return self.status == ScanStatus.COMPLETED

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def has_errors(self) -> bool:
        return bool(self.errors)

    def to_dict(self) -> dict[str, Any]:
        payload = self.model_dump(mode="json")
        payload["scan"] = dict(payload)
        payload["scan"]["execution"] = self.execution.model_dump(
            mode="json"
        )
        payload["pipeline"] = (
            self.pipeline.to_dict()
            if self.pipeline is not None
            and hasattr(self.pipeline, "to_dict")
            else self.pipeline
        )
        payload["findings"] = [
            finding.model_dump(mode="json")
            if hasattr(finding, "model_dump")
            else finding
            for finding in self.findings
        ]
        return payload
