"""Release-gate models for SecureForge."""
from __future__ import annotations
from dataclasses import dataclass,field
from enum import Enum
from typing import Any
class ReleaseDecision(str,Enum):
    PASS="pass";REVIEW="review";BLOCK="block";BLOCKED="block"
class ReleaseGateStatus(str,Enum):
    PASSED="passed";REVIEW="review";BLOCKED="blocked";PASS="passed";BLOCK="blocked"
@dataclass
class ReleaseGateInput:
    application:str="";version:str="";commit_sha:str|None=None
    policy_decision:ReleaseDecision=ReleaseDecision.PASS
    blocking_findings:list[str]=field(default_factory=list);review_findings:list[str]=field(default_factory=list)
    failed_regressions:list[str]=field(default_factory=list);tool_errors:list[str]=field(default_factory=list)
    exceptions_applied:list[str]=field(default_factory=list);metadata:dict[str,Any]=field(default_factory=dict)
@dataclass(init=False)
class ReleaseGateDecision:
    def __init__(self,application="",version="",commit_sha=None,decision=None,reasons=None,blocking_findings=None,
                 review_findings=None,failed_regressions=None,tool_errors=None,exceptions_applied=None,metadata=None,
                 *,status=None,reason=None,release_allowed=None):
        raw=decision if decision is not None else status
        if raw is None:raw=ReleaseDecision.BLOCK if release_allowed is False else ReleaseDecision.PASS
        raw=getattr(raw,"value",raw)
        aliases={"passed":ReleaseDecision.PASS,"pass":ReleaseDecision.PASS,"review":ReleaseDecision.REVIEW,"blocked":ReleaseDecision.BLOCK,"block":ReleaseDecision.BLOCK}
        self.decision=raw if isinstance(raw,ReleaseDecision) else aliases.get(str(raw).lower(),ReleaseDecision(str(raw)))
        self.application=application;self.version=version;self.commit_sha=commit_sha
        self.reasons=list(reasons) if reasons is not None else ([reason] if reason else [])
        self.blocking_findings=list(blocking_findings or []);self.review_findings=list(review_findings or [])
        self.failed_regressions=list(failed_regressions or []);self.tool_errors=list(tool_errors or [])
        self.exceptions_applied=list(exceptions_applied or []);self.metadata=dict(metadata or {})
        if release_allowed is not None and release_allowed!=self.release_allowed:raise ValueError("release_allowed conflicts with the release decision.")
    @property
    def passed(self):return self.decision==ReleaseDecision.PASS
    @property
    def requires_review(self):return self.decision==ReleaseDecision.REVIEW
    @property
    def review_required(self):return self.requires_review
    @property
    def is_blocked(self):return self.decision==ReleaseDecision.BLOCK
    @property
    def blocked(self):return self.is_blocked
    @property
    def release_allowed(self):return not self.is_blocked
    @property
    def status(self):return "passed" if self.passed else "review" if self.requires_review else "blocked"
    @property
    def reason(self):return " ".join(self.reasons)
    def to_dict(self):
        return {"application":self.application,"version":self.version,"commit_sha":self.commit_sha,"decision":self.decision.value,"status":self.status,"release_allowed":self.release_allowed,"passed":self.passed,"requires_review":self.requires_review,"review_required":self.review_required,"is_blocked":self.is_blocked,"blocked":self.blocked,"blocking_findings":self.blocking_findings,"review_findings":self.review_findings,"failed_regressions":self.failed_regressions,"tool_errors":self.tool_errors,"exceptions_applied":self.exceptions_applied,"reasons":self.reasons,"metadata":self.metadata}
ReleaseDecisionRecord=ReleaseGateDecision
ReleaseGateAction=ReleaseDecision
