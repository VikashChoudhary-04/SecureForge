"""Release-gate models for SecureForge."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ReleaseDecision(str, Enum):
    """Final release decision produced by SecureForge."""

    PASS = "pass"
    REVIEW = "review"
    BLOCK = "block"

    # Compatibility name used by release-gate fixtures and callers.
    BLOCKED = "block"


@dataclass
class ReleaseGateInput:
    """Input conditions evaluated by the release gate."""

    application: str
    version: str
    commit_sha: str | None = None
    policy_decision: ReleaseDecision = ReleaseDecision.PASS
    blocking_findings: list[str] = field(default_factory=list)
    review_findings: list[str] = field(default_factory=list)
    failed_regressions: list[str] = field(default_factory=list)
    tool_errors: list[str] = field(default_factory=list)
    exceptions_applied: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(init=False)
class ReleaseGateDecision:
    """Final release-gate result.

    Supports both the current structured decision contract and the
    legacy status/reason/release_allowed construction used by callers.
    """

    application: str
    version: str
    commit_sha: str | None
    decision: ReleaseDecision
    reasons: list[str] = field(default_factory=list)
    blocking_findings: list[str] = field(default_factory=list)
    review_findings: list[str] = field(default_factory=list)
    failed_regressions: list[str] = field(default_factory=list)
    tool_errors: list[str] = field(default_factory=list)
    exceptions_applied: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __init__(
        self,
        application: str = "",
        version: str = "",
        commit_sha: str | None = None,
        decision: ReleaseDecision | str | None = None,
        reasons: list[str] | None = None,
        blocking_findings: list[str] | None = None,
        review_findings: list[str] | None = None,
        failed_regressions: list[str] | None = None,
        tool_errors: list[str] | None = None,
        exceptions_applied: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        *,
        status: ReleaseDecision | str | None = None,
        reason: str | None = None,
        release_allowed: bool | None = None,
    ) -> None:
        """Create a release decision with current and legacy inputs."""
        if decision is None:
            if status is not None:
                if isinstance(status, ReleaseDecision):
                    decision = status
                else:
                    decision = ReleaseDecision(str(status))
            elif release_allowed is False:
                decision = ReleaseDecision.BLOCK
            else:
                decision = ReleaseDecision.PASS
        elif not isinstance(decision, ReleaseDecision):
            decision = ReleaseDecision(decision)

        if reasons is None:
            reasons = [reason] if reason else []

        self.application = application
        self.version = version
        self.commit_sha = commit_sha
        self.decision = decision
        self.reasons = reasons
        self.blocking_findings = (
            blocking_findings
            if blocking_findings is not None
            else []
        )
        self.review_findings = (
            review_findings
            if review_findings is not None
            else []
        )
        self.failed_regressions = (
            failed_regressions
            if failed_regressions is not None
            else []
        )
        self.tool_errors = (
            tool_errors
            if tool_errors is not None
            else []
        )
        self.exceptions_applied = (
            exceptions_applied
            if exceptions_applied is not None
            else []
        )
        self.metadata = (
            metadata
            if metadata is not None
            else {}
        )

        if release_allowed is not None:
            expected_allowed = not self.is_blocked
            if release_allowed != expected_allowed:
                raise ValueError(
                    "release_allowed conflicts with the release decision."
                )

    @property
    def passed(self) -> bool:
        """Return whether the release passed."""
        return self.decision == ReleaseDecision.PASS

    @property
    def requires_review(self) -> bool:
        """Return whether the release requires review."""
        return self.decision == ReleaseDecision.REVIEW

    @property
    def is_blocked(self) -> bool:
        """Return whether the release is blocked."""
        return self.decision == ReleaseDecision.BLOCK

    @property
    def release_allowed(self) -> bool:
        """Return whether the release is allowed."""
        return not self.is_blocked

    @property
    def blocked(self) -> bool:
        """Return whether the release is blocked."""
        return self.is_blocked

    @property
    def status(self) -> str:
        """Return the decision as a string status."""
        return self.decision.value

    @property
    def reason(self) -> str:
        """Return the combined release-gate reasons."""
        return " ".join(self.reasons)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the release decision."""
        return {
            "application": self.application,
            "version": self.version,
            "commit_sha": self.commit_sha,
            "decision": self.decision.value,
            "status": self.status,
            "release_allowed": self.release_allowed,
            "passed": self.passed,
            "requires_review": self.requires_review,
            "is_blocked": self.is_blocked,
            "blocking_findings": self.blocking_findings,
            "review_findings": self.review_findings,
            "failed_regressions": self.failed_regressions,
            "tool_errors": self.tool_errors,
            "exceptions_applied": self.exceptions_applied,
            "reasons": self.reasons,
            "metadata": self.metadata,
        }


# Compatibility aliases used by other SecureForge components.
ReleaseDecisionRecord = ReleaseGateDecision
ReleaseGateAction = ReleaseDecision
ReleaseGateStatus = ReleaseDecision


__all__ = [
    "ReleaseDecision",
    "ReleaseDecisionRecord",
    "ReleaseGateAction",
    "ReleaseGateStatus",
    "ReleaseGateInput",
    "ReleaseGateDecision",
]
