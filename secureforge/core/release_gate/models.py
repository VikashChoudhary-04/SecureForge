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


@dataclass
class ReleaseGateDecision:
    """Final release-gate result."""

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


ReleaseGateAction = ReleaseDecision
ReleaseGateStatus = ReleaseDecision


__all__ = [
    "ReleaseDecision",
    "ReleaseGateAction",
    "ReleaseGateStatus",
    "ReleaseGateInput",
    "ReleaseGateDecision",
]
