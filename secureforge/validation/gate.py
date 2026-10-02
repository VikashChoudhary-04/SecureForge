"""Validation gate evaluation."""

from __future__ import annotations

from dataclasses import dataclass

from .models import ValidationOutcome
from .runner import RetestRun, ValidationRun


@dataclass(frozen=True)
class ValidationGateDecision:
    """Decision produced by the validation gate."""

    allowed: bool
    status: str
    reason: str
    confirmed_findings: tuple[str, ...]
    unresolved_findings: tuple[str, ...]
    remediation_verified: tuple[str, ...]
    inconclusive_findings: tuple[str, ...]
    errored_findings: tuple[str, ...]

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"

    @property
    def requires_attention(self) -> bool:
        return bool(
            self.unresolved_findings
            or self.inconclusive_findings
            or self.errored_findings
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "blocked": self.blocked,
            "status": self.status,
            "reason": self.reason,
            "confirmed_findings": list(self.confirmed_findings),
            "unresolved_findings": list(self.unresolved_findings),
            "remediation_verified": list(self.remediation_verified),
            "inconclusive_findings": list(self.inconclusive_findings),
            "errored_findings": list(self.errored_findings),
            "requires_attention": self.requires_attention,
        }


def evaluate_validation_run(
    run: ValidationRun,
) -> ValidationGateDecision:
    """Evaluate validation results without replacing release policy."""
    confirmed: list[str] = []
    unresolved: list[str] = []
    inconclusive: list[str] = []
    errored: list[str] = []
    remediated: list[str] = []

    for result in run.results:
        if result.outcome == ValidationOutcome.CONFIRMED:
            confirmed.append(result.finding_id)
            unresolved.append(result.finding_id)
        elif result.outcome == ValidationOutcome.INCONCLUSIVE:
            inconclusive.append(result.finding_id)
            unresolved.append(result.finding_id)
        elif result.outcome == ValidationOutcome.ERROR:
            errored.append(result.finding_id)
            unresolved.append(result.finding_id)

        if (
            result.outcome == ValidationOutcome.REJECTED
            and result.remediation_verified
        ):
            remediated.append(result.finding_id)

    if confirmed:
        return ValidationGateDecision(
            allowed=False,
            status="blocked",
            reason=(
                "Security validation confirmed one or more findings."
            ),
            confirmed_findings=tuple(confirmed),
            unresolved_findings=tuple(unresolved),
            remediation_verified=tuple(remediated),
            inconclusive_findings=tuple(inconclusive),
            errored_findings=tuple(errored),
        )

    if errored:
        return ValidationGateDecision(
            allowed=False,
            status="error",
            reason=(
                "One or more validation attempts failed to complete."
            ),
            confirmed_findings=(),
            unresolved_findings=tuple(unresolved),
            remediation_verified=tuple(remediated),
            inconclusive_findings=tuple(inconclusive),
            errored_findings=tuple(errored),
        )

    if inconclusive:
        return ValidationGateDecision(
            allowed=False,
            status="review",
            reason=(
                "One or more validation results were inconclusive."
            ),
            confirmed_findings=(),
            unresolved_findings=tuple(unresolved),
            remediation_verified=tuple(remediated),
            inconclusive_findings=tuple(inconclusive),
            errored_findings=(),
        )

    return ValidationGateDecision(
        allowed=True,
        status="passed",
        reason=(
            "Security validation completed without confirmed findings."
        ),
        confirmed_findings=(),
        unresolved_findings=(),
        remediation_verified=tuple(remediated),
        inconclusive_findings=(),
        errored_findings=(),
    )


def evaluate_retest_run(
    run: RetestRun,
) -> ValidationGateDecision:
    """Evaluate retest results after remediation."""
    confirmed: list[str] = []
    unresolved: list[str] = []
    inconclusive: list[str] = []
    errored: list[str] = []
    remediated: list[str] = []

    for result in run.results:
        if result.remediation_verified:
            remediated.append(result.finding_id)

        if result.current_outcome == ValidationOutcome.CONFIRMED:
            confirmed.append(result.finding_id)
            unresolved.append(result.finding_id)
        elif result.current_outcome == ValidationOutcome.INCONCLUSIVE:
            inconclusive.append(result.finding_id)
            unresolved.append(result.finding_id)
        elif result.current_outcome == ValidationOutcome.ERROR:
            errored.append(result.finding_id)
            unresolved.append(result.finding_id)

    if confirmed:
        return ValidationGateDecision(
            allowed=False,
            status="blocked",
            reason=(
                "Retesting confirmed that one or more previously "
                "identified findings remain."
            ),
            confirmed_findings=tuple(confirmed),
            unresolved_findings=tuple(unresolved),
            remediation_verified=tuple(remediated),
            inconclusive_findings=tuple(inconclusive),
            errored_findings=tuple(errored),
        )

    if errored:
        return ValidationGateDecision(
            allowed=False,
            status="error",
            reason=(
                "One or more remediation retests failed to complete."
            ),
            confirmed_findings=(),
            unresolved_findings=tuple(unresolved),
            remediation_verified=tuple(remediated),
            inconclusive_findings=tuple(inconclusive),
            errored_findings=tuple(errored),
        )

    if inconclusive:
        return ValidationGateDecision(
            allowed=False,
            status="review",
            reason=(
                "One or more remediation retests were inconclusive."
            ),
            confirmed_findings=(),
            unresolved_findings=tuple(unresolved),
            remediation_verified=tuple(remediated),
            inconclusive_findings=tuple(inconclusive),
            errored_findings=(),
        )

    return ValidationGateDecision(
        allowed=True,
        status="passed",
        reason=(
            "All remediation retests completed without confirmed findings."
        ),
        confirmed_findings=(),
        unresolved_findings=(),
        remediation_verified=tuple(remediated),
        inconclusive_findings=(),
        errored_findings=(),
    )


__all__ = [
    "ValidationGateDecision",
    "evaluate_retest_run",
    "evaluate_validation_run",
]
