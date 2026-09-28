```python id="9q3v1m"
"""Tests for the SecureForge validation runner."""

from secureforge.validation.base import BaseValidator
from secureforge.validation.engine import ValidationEngine
from secureforge.validation.models import (
    ValidationMethod,
    ValidationOutcome,
    ValidationRequest,
    ValidationResult,
)
from secureforge.validation.registry import ValidatorRegistry
from secureforge.validation.retest import RetestService
from secureforge.validation.runner import (
    RetestRun,
    ValidationRun,
    ValidationRunner,
)
from secureforge.validation.service import ValidationService


class RunnerValidator(BaseValidator):
    """Deterministic validator for runner tests."""

    name = "runner-test"

    def supports(self, request: ValidationRequest) -> bool:
        return request.method == ValidationMethod.MANUAL

    def validate(self, request: ValidationRequest) -> ValidationResult:
        outcome = request.metadata.get(
            "outcome",
            "confirmed",
        )

        return ValidationResult(
            finding_id=request.finding_id,
            outcome=ValidationOutcome(outcome),
            message=f"Validation result: {outcome}.",
            validator=self.name,
            validated_at="2026-09-28T09:00:00+05:30",
        )


def build_runner() -> ValidationRunner:
    registry = ValidatorRegistry(
        validators=[RunnerValidator()]
    )
    engine = ValidationEngine(registry)
    service = ValidationService(engine)
    retest_service = RetestService(service)

    return ValidationRunner(
        validation_service=service,
        retest_service=retest_service,
    )


def build_request(
    finding_id: str,
    *,
    outcome: str,
) -> ValidationRequest:
    return ValidationRequest(
        finding_id=finding_id,
        target="http://localhost:5000",
        method=ValidationMethod.MANUAL,
        metadata={
            "outcome": outcome,
        },
    )


def test_runner_returns_validation_run() -> None:
    runner = build_runner()

    run = runner.run(
        [
            build_request(
                "SQLI-001",
                outcome="confirmed",
            ),
            build_request(
                "XSS-001",
                outcome="rejected",
            ),
        ]
    )

    assert isinstance(run, ValidationRun)
    assert run.summary.total == 2
    assert len(run.results) == 2
    assert run.successful is True


def test_validation_run_reports_errors() -> None:
    runner = build_runner()

    run = runner.run(
        [
            build_request(
                "SECRET-001",
                outcome="error",
            ),
        ]
    )

    assert run.successful is False
    assert run.summary.errors == 1


def test_runner_preserves_validation_order() -> None:
    runner = build_runner()

    run = runner.run(
        [
            build_request(
                "FINDING-001",
                outcome="confirmed",
            ),
            build_request(
                "FINDING-002",
                outcome="rejected",
            ),
            build_request(
                "FINDING-003",
                outcome="inconclusive",
            ),
        ]
    )

    assert [
        result.finding_id
        for result in run.results
    ] == [
        "FINDING-001",
        "FINDING-002",
        "FINDING-003",
    ]


def test_runner_returns_retest_run() -> None:
    runner = build_runner()

    run = runner.retest(
        [
            (
                build_request(
                    "SQLI-001",
                    outcome="rejected",
                ),
                ValidationOutcome.CONFIRMED,
            ),
            (
                build_request(
                    "BOLA-001",
                    outcome="confirmed",
                ),
                ValidationOutcome.CONFIRMED,
            ),
        ]
    )

    assert isinstance(run, RetestRun)
    assert run.total == 2
    assert run.fixed == 1
    assert run.still_confirmed == 1
    assert run.inconclusive == 0
    assert run.errors == 0
    assert run.regression_required is True


def test_retest_run_counts_inconclusive_results() -> None:
    runner = build_runner()

    run = runner.retest(
        [
            (
                build_request(
                    "XSS-001",
                    outcome="inconclusive",
                ),
                ValidationOutcome.CONFIRMED,
            ),
        ]
    )

    assert run.total == 1
    assert run.fixed == 0
    assert run.still_confirmed == 0
    assert run.inconclusive == 1
    assert run.errors == 0
    assert run.regression_required is False


def test_retest_run_counts_errors() -> None:
    runner = build_runner()

    run = runner.retest(
        [
            (
                build_request(
                    "SECRET-001",
                    outcome="error",
                ),
                ValidationOutcome.CONFIRMED,
            ),
        ]
    )

    assert run.total == 1
    assert run.fixed == 0
    assert run.still_confirmed == 0
    assert run.inconclusive == 0
    assert run.errors == 1
    assert run.regression_required is False
```
