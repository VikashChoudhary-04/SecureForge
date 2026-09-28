"""Release-gate decision models for SecureForge."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ReleaseGateDecision:
    """Final decision produced by the SecureForge release gate."""

    release_allowed: bool
    status: str
    reason: str

    @property
    def blocked(self) -> bool:
        """Return whether the release is blocked."""
        return not self.release_allowed

    @property
    def passed(self) -> bool:
        """Return whether the release passed."""
        return self.release_allowed and self.status == "passed"

    @property
    def review_required(self) -> bool:
        """Return whether the release requires review."""
        return self.release_allowed and self.status == "review"

    def to_dict(self) -> dict[str, Any]:
        """Serialize the decision into report-friendly data."""
        return {
            "release_allowed": self.release_allowed,
            "status": self.status,
            "reason": self.reason,
            "blocked": self.blocked,
            "passed": self.passed,
            "review_required": self.review_required,
        }


__all__ = [
    "ReleaseGateDecision",
]
