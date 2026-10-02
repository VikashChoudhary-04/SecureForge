"""Policy models used by the SecureForge release gate."""

from __future__ import annotations

from enum import Enum
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field


class PolicyAction(str, Enum):
    """Action produced when a policy condition is triggered."""

    PASS = "pass"
    REVIEW = "review"
    BLOCK = "block"


class PolicyDecision(BaseModel):
    """Final decision produced by policy evaluation."""

    model_config = ConfigDict(extra="allow")

    policy_name: str = "default"
    action: PolicyAction = PolicyAction.REVIEW
    allowed: bool = False
    reason: str = ""
    violations: list[str] = Field(default_factory=list)

    PASS: ClassVar["PolicyDecision"]
    REVIEW: ClassVar["PolicyDecision"]
    BLOCK: ClassVar["PolicyDecision"]

    def __init__(self, value: str | PolicyAction | None = None, **data: Any):
        legacy_actions = data.get("actions")
        if "action" not in data and isinstance(legacy_actions, dict):
            high = str(legacy_actions.get("high", "")).lower()
            critical = str(legacy_actions.get("critical", "")).lower()
            if "block" in {high, critical}:
                data["action"] = PolicyAction.BLOCK
                data["allowed"] = False

        if value is not None:
            if data:
                raise TypeError(
                    "Positional decision value cannot be combined "
                    "with keyword fields."
                )
            action = PolicyAction(value)
            data = {
                "action": action,
                "allowed": action == PolicyAction.PASS,
                "policy_name": "default",
            }

        super().__init__(**data)

    @property
    def value(self) -> str:
        return self.action.value

    def __eq__(self, other: object) -> bool:
        if isinstance(other, PolicyDecision):
            return self.action == other.action
        if isinstance(other, PolicyAction):
            return self.action == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.action)


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="allow")

    rule_id: str
    name: str
    description: str
    severity: str | None = None
    risk_level: str | None = None
    action: PolicyAction
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyException(BaseModel):
    model_config = ConfigDict(extra="allow")

    exception_id: str
    finding_id: str | None = None
    requirement_id: str | None = None
    reason: str
    approved_by: str | None = None
    expires_at: str | None = None
    compensating_control: str | None = None
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    policy_id: str
    version: str
    rules: list[PolicyRule] = Field(default_factory=list)
    exceptions: list[PolicyException] = Field(default_factory=list)
    fail_on_tool_error: bool = False
    fail_on_regression_failure: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyEvaluation(BaseModel):
    model_config = ConfigDict(extra="allow")

    decision: PolicyDecision
    triggered_rules: list[str] = Field(default_factory=list)
    blocking_findings: list[str] = Field(default_factory=list)
    review_findings: list[str] = Field(default_factory=list)
    passed_findings: list[str] = Field(default_factory=list)
    exceptions_applied: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    policy_id: str
    policy_version: str


PolicyDecision.PASS = PolicyDecision(action=PolicyAction.PASS, allowed=True)
PolicyDecision.REVIEW = PolicyDecision(action=PolicyAction.REVIEW, allowed=False)
PolicyDecision.BLOCK = PolicyDecision(action=PolicyAction.BLOCK, allowed=False)
