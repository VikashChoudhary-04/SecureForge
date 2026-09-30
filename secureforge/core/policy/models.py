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
    """Final decision produced by policy evaluation.

    The model supports both the structured decision contract and the
    enum-like PASS/REVIEW/BLOCK constants used by the policy engine.
    """

    model_config = ConfigDict(extra="allow")

    policy_name: str = "default"
    action: PolicyAction
    allowed: bool
    reason: str = ""
    violations: list[str] = Field(default_factory=list)

    PASS: ClassVar["PolicyDecision"]
    REVIEW: ClassVar["PolicyDecision"]
    BLOCK: ClassVar["PolicyDecision"]

    def __init__(
        self,
        value: str | PolicyAction | None = None,
        **data: Any,
    ) -> None:
        """Create a structured decision or an enum-style decision."""
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

    def __eq__(self, other: object) -> bool:
        """Compare decisions by their policy action."""
        if isinstance(other, PolicyDecision):
            return self.action == other.action

        if isinstance(other, PolicyAction):
            return self.action == other

        return NotImplemented

    def __hash__(self) -> int:
        """Hash decisions by their policy action."""
        return hash(self.action)


class PolicyRule(BaseModel):
    """A single configurable security policy rule."""

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
    """Explicit exception to a security policy decision."""

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
    """Complete SecureForge policy configuration."""

    model_config = ConfigDict(extra="allow")

    policy_id: str
    version: str

    rules: list[PolicyRule] = Field(default_factory=list)

    exceptions: list[PolicyException] = Field(default_factory=list)

    fail_on_tool_error: bool = False

    fail_on_regression_failure: bool = True

    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyEvaluation(BaseModel):
    """Result produced after evaluating findings against policy."""

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


# Enum-style decision constants retained for compatibility with the
# policy engine and existing callers.
PolicyDecision.model_rebuild()

PolicyDecision.PASS = PolicyDecision(
    action=PolicyAction.PASS,
    allowed=True,
)
PolicyDecision.REVIEW = PolicyDecision(
    action=PolicyAction.REVIEW,
    allowed=False,
)
PolicyDecision.BLOCK = PolicyDecision(
    action=PolicyAction.BLOCK,
    allowed=False,
)
