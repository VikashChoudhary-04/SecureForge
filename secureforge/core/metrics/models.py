"""Security metrics models for SecureForge."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class FindingMetrics:
    """Aggregate finding metrics for a collection of findings."""

    total: int = 0

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0

    open: int = 0
    in_progress: int = 0
    validated: int = 0
    rejected: int = 0
    remediated: int = 0
    verified: int = 0
    accepted: int = 0
    reopened: int = 0

    confirmed: int = 0
    unconfirmed: int = 0

    false_positive_rate: float | None = None

    requirements_violated: int = 0
    recurring: int = 0


@dataclass(frozen=True)
class ReleaseMetrics:
    """Aggregate release-gate outcomes."""

    evaluated: int = 0
    passed: int = 0
    reviewed: int = 0
    blocked: int = 0

    blocking_conditions: int = 0
    review_conditions: int = 0

    @property
    def pass_rate(self) -> float | None:
        """Return the percentage of evaluated releases that passed."""
        if self.evaluated == 0:
            return None

        return self.passed / self.evaluated

    @property
    def review_rate(self) -> float | None:
        """Return the percentage of evaluated releases requiring review."""
        if self.evaluated == 0:
            return None

        return self.reviewed / self.evaluated

    @property
    def block_rate(self) -> float | None:
        """Return the percentage of evaluated releases that were blocked."""
        if self.evaluated == 0:
            return None

        return self.blocked / self.evaluated


@dataclass(frozen=True)
class RegressionMetrics:
    """Aggregate regression-test outcomes."""

    total_failures: int = 0
    failed_tests: tuple[str, ...] = ()


@dataclass(frozen=True)
class RequirementMetrics:
    """Aggregate requirement coverage and violation metrics."""

    evaluated: int = 0
    violated: int = 0
    satisfied: int = 0

    @property
    def satisfaction_rate(self) -> float | None:
        """Return the proportion of evaluated requirements satisfied."""
        if self.evaluated == 0:
            return None

        return self.satisfied / self.evaluated


@dataclass(frozen=True)
class RemediationMetrics:
    """Aggregate remediation timing information."""

    remediated: int = 0
    verified: int = 0

    mttr_seconds: float | None = None
    mttr_available: bool = False


@dataclass(frozen=True)
class SecurityMetrics:
    """Complete security metrics snapshot for SecureForge."""

    findings: FindingMetrics = field(
        default_factory=FindingMetrics
    )
    releases: ReleaseMetrics = field(
        default_factory=ReleaseMetrics
    )
    regression: RegressionMetrics = field(
        default_factory=RegressionMetrics
    )
    requirements: RequirementMetrics = field(
        default_factory=RequirementMetrics
    )
    remediation: RemediationMetrics = field(
        default_factory=RemediationMetrics
    )
