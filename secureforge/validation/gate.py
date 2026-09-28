```python id="1w6c4r"
"""Validation gate decisions for SecureForge."""

from __future__ import annotations

from dataclasses import dataclass

from .models import ValidationOutcome, ValidationResult
from .runner import RetestRun, ValidationRun


@dataclass(frozen=True)
class ValidationGateDecision:
    """Decision produced from validation or retesting results."""

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
        """Return whether the validation gate blocks progression."""
        return not self.allowed

    @property
    def requires_attention(self) -> bool:
        """Return whether further security action is required."""
        return bool(
            self.unresolved_findings
            or self.inconclusive_findings
            or self.errored_findings
        )


def evaluate_validation_run(
    run: ValidationRun,
) -> ValidationGateDecision:
    """Evaluate a validation run for release progression."""
    confirmed = tuple(
        result.finding_id
        for result in run.results
        if result.outcome == ValidationOutcome.CONFIRMED
    )

    inconclusive = tuple(
        result.finding_id
        for result in run.results
        if result.outcome == ValidationOutcome.INCONCLUSIVE
    )

    errored = tuple(
        result.finding_id
        for result in run.results
        if result.outcome == ValidationOutcome.ERROR
    )

    remediation_verified = tuple(
        result.finding_id
        for result in run.results
        if result.remediation_verified
    )

    unresolved = tuple(
        result.finding_id
        for result in run.results
        if (
            result.outcome == ValidationOutcome.CONFIRMED
            or result.outcome == ValidationOutcome.INCONCLUSIVE
            or result.outcome == ValidationOutcome.ERROR
        )
    )

    if confirmed:
        return ValidationGateDecision(
            allowed=False,
            status="blocked",
            reason=(
                "One or more security findings were confirmed "
                "during validation."
            ),
            confirmed_findings=confirmed,
            unresolved_findings=unresolved,
            remediation_verified=remediation_verified,
            inconclusive_findings=inconclusive,
            errored_findings=errored,
        )

    if errored:
        return ValidationGateDecision(
            allowed=False,
            status="error",
            reason=(
                "Validation encountered errors, so security "
                "verification is incomplete."
            ),
            confirmed_findings=confirmed,
            unresolved_findings=unresolved,
            remediation_verified=remediation_verified,
            inconclusive_findings=inconclusive,
            errored_findings=errored,
        )

    if inconclusive:
        return ValidationGateDecision(
            allowed=False,
            status="review",
            reason=(
                "One or more findings could not be conclusively "
                "validated."
            ),
            confirmed_findings=confirmed,
            unresolved_findings=unresolved,
            remediation_verified=remediation_verified,
            inconclusive_findings=inconclusive,
            errored_findings=errored,
        )

    return ValidationGateDecision(
        allowed=True,
        status="passed",
        reason=(
            "All supplied findings were rejected by validation "
            "and no validation errors occurred."
        ),
        confirmed_findings=confirmed,
        unresolved_findings=unresolved,
        remediation_verified=remediation_verified,
        inconclusive_findings=inconclusive,
        errored_findings=errored,
    )


def evaluate_retest_run(
    run: RetestRun,
) -> ValidationGateDecision:
    """Evaluate remediation retesting for release progression."""
    confirmed = tuple(
        result.finding_id
        for result in run.results
        if result.current_outcome == ValidationOutcome.CONFIRMED
    )

    inconclusive = tuple(
        result.finding_id
        for result in run.results
        if result.current_outcome == ValidationOutcome.INCONCLUSIVE
    )

    errored = tuple(
        result.finding_id
        for result in run.results
        if result.current_outcome == ValidationOutcome.ERROR
    )

    remediation_verified = tuple(
        result.finding_id
        for result in run.results
        if result.remediation_verified
    )

    unresolved = tuple(
        result.finding_id
        for result in run.results
        if (
            result.current_outcome == ValidationOutcome.CONFIRMED
            or result.current_outcome == ValidationOutcome.INCONCLUSIVE
            or result.current_outcome == ValidationOutcome.ERROR
        )
    )

    if confirmed:
        return ValidationGateDecision(
            allowed=False,
            status="blocked",
            reason=(
                "One or more previously identified findings "
                "remain reproducible after remediation."
            ),
            confirmed_findings=confirmed,
            unresolved_findings=unresolved,
            remediation_verified=remediation_verified,
            inconclusive_findings=inconclusive,
            errored_findings=errored,
        )

    if errored:
        return ValidationGateDecision(
            allowed=False,
            status="error",
            reason=(
                "One or more remediation retests failed to "
                "complete."
            ),
            confirmed_findings=confirmed,
            unresolved_findings=unresolved,
            remediation_verified=remediation_verified,
            inconclusive_findings=inconclusive,
            errored_findings=errored,
        )

    if inconclusive:
        return ValidationGateDecision(
            allowed=False,
            status="review",
            reason=(
                "One or more remediation retests were "
                "inconclusive."
            ),
            confirmed_findings=confirmed,
            unresolved_findings=unresolved,
            remediation_verified=remediation_verified,
            inconclusive_findings=inconclusive,
            errored_findings=errored,
        )

    return ValidationGateDecision(
        allowed=True,
        status="passed",
        reason=(
            "All supplied remediation retests completed without "
            "reproducing the previously identified findings."
        ),
        confirmed_findings=confirmed,
        unresolved_findings=unresolved,
        remediation_verified=remediation_verified,
        inconclusive_findings=inconclusive,
        errored_findings=errored,
    )
```
