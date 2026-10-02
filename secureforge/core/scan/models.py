"""Models used by SecureForge scan orchestration."""
from __future__ import annotations
from datetime import datetime,timezone
from enum import Enum
from typing import Any
from pydantic import BaseModel,ConfigDict,Field
from secureforge.core.config import ScanProfile
from secureforge.core.findings import Finding
from secureforge.core.policy import PolicyEvaluation
from secureforge.core.release_gate import ReleaseDecisionRecord
from secureforge.core.risk import RiskAssessment
def utc_now():return datetime.now(timezone.utc)
class ScanStatus(str,Enum):
    CREATED="created";RUNNING="running";COMPLETED="completed";FAILED="failed"
class ToolExecutionStatus(str,Enum):
    NOT_STARTED="not_started";RUNNING="running";SUCCESS="success";FAILED="failed";SKIPPED="skipped";TIMEOUT="timeout"
class RawEvidence(BaseModel):
    model_config=ConfigDict(extra="allow")
    source:str;source_version:str="unknown";source_reference:str|None=None;target:Any|None=None;raw_data:Any=None
    collected_at:datetime=Field(default_factory=utc_now);metadata:dict[str,Any]=Field(default_factory=dict)
class ScanConfiguration(BaseModel):
    model_config=ConfigDict(extra="allow")
    application:str;version:str;profile:ScanProfile=ScanProfile.STANDARD;environment:str="development"
    commit_sha:str|None=None;target:str|None=None;metadata:dict[str,Any]=Field(default_factory=dict)
class ToolExecutionResult(BaseModel):
    model_config=ConfigDict(extra="allow")
    tool_name:str;integration:str;status:ToolExecutionStatus;command:list[str]=Field(default_factory=list)
    exit_code:int|None=None;stdout:str="";stderr:str="";duration_seconds:float=Field(default=0.0,ge=0.0)
    evidence_path:str|None=None;error:str|None=None;started_at:datetime|None=None;completed_at:datetime|None=None
    metadata:dict[str,Any]=Field(default_factory=dict)
    @property
    def succeeded(self):return self.status==ToolExecutionStatus.SUCCESS
    @property
    def failed(self):return self.status in {ToolExecutionStatus.FAILED,ToolExecutionStatus.TIMEOUT}
class ScanExecution(BaseModel):
    model_config=ConfigDict(extra="allow")
    scan_id:str;profile:str;application:str="securecommerce";version:str="1.0.0";commit_sha:str|None=None;environment:str="lab"
    target:str|None=None;started_at:str;completed_at:str;status:ScanStatus|str=ScanStatus.COMPLETED
    tools:list[ToolExecutionResult]=Field(default_factory=list);tool_errors:list[str]=Field(default_factory=list);metadata:dict[str,Any]=Field(default_factory=dict)
class ScanSummary(BaseModel):
    model_config=ConfigDict(extra="allow")
    tool_count:int=0;successful_tools:int=0;failed_tools:int=0;skipped_tools:int=0;finding_count:int=0
    critical_findings:int=0;high_findings:int=0;medium_findings:int=0;low_findings:int=0;info_findings:int=0;correlated_group_count:int=0;regression_failure_count:int=0
    def update_findings(self,findings):
        self.finding_count=len(findings)
        self.critical_findings=sum(f.severity.value=="critical" for f in findings)
        self.high_findings=sum(f.severity.value=="high" for f in findings)
        self.medium_findings=sum(f.severity.value=="medium" for f in findings)
        self.low_findings=sum(f.severity.value=="low" for f in findings)
        self.info_findings=sum(f.severity.value in {"info","informational"} for f in findings)
class ScanRun(BaseModel):
    model_config=ConfigDict(extra="allow")
    scan_id:str;application:str;version:str;profile:ScanProfile;environment:str;status:ScanStatus=ScanStatus.CREATED
    commit_sha:str|None=None;started_at:datetime=Field(default_factory=utc_now);completed_at:datetime|None=None
    tool_results:list[ToolExecutionResult]=Field(default_factory=list);findings:list[Finding]=Field(default_factory=list)
    risk_assessments:list[RiskAssessment]=Field(default_factory=list);policy_evaluation:PolicyEvaluation|None=None
    release_decision:ReleaseDecisionRecord|None=None;regression_failures:list[str]=Field(default_factory=list)
    errors:list[str]=Field(default_factory=list);warnings:list[str]=Field(default_factory=list);summary:ScanSummary=Field(default_factory=ScanSummary);metadata:dict[str,Any]=Field(default_factory=dict)
class SecurityScanResult(BaseModel):
    model_config=ConfigDict(extra="allow")
    execution:ScanExecution;findings:list[Finding]=Field(default_factory=list);pipeline:Any|None=None
    scan_id:str|None=None;application:str|None=None;version:str|None=None;profile:str|None=None;environment:str|None=None
    status:ScanStatus|str=ScanStatus.COMPLETED;commit_sha:str|None=None;risk_assessments:list[RiskAssessment]=Field(default_factory=list)
    policy_evaluation:PolicyEvaluation|None=None;release_decision:ReleaseDecisionRecord|None=None
    tool_results:list[ToolExecutionResult]=Field(default_factory=list);regression_failures:list[str]=Field(default_factory=list)
    errors:list[str]=Field(default_factory=list);warnings:list[str]=Field(default_factory=list);summary:ScanSummary=Field(default_factory=ScanSummary);metadata:dict[str,Any]=Field(default_factory=dict)
    @property
    def target(self):return self.execution.target
    @property
    def release_gate(self):return getattr(self.pipeline,"release_gate",self.release_decision)
    @property
    def release_allowed(self):return bool(getattr(self.release_gate,"release_allowed",False))
    @property
    def release_blocked(self):return not self.release_allowed
    @property
    def passed(self):return self.status==ScanStatus.COMPLETED
    @property
    def has_findings(self):return bool(self.findings)
    @property
    def has_errors(self):return bool(self.errors)
    def to_dict(self):return self.model_dump(mode="json")
