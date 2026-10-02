"""Assessment helpers for SecureForge regression results."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import RegressionStatus, RegressionSuiteResult


@dataclass(frozen=True)
class RegressionAssessment:
    """Summarize regression results for release-gate evaluation."""

    suite_id: str
    suite_name: str
    status: RegressionStatus
    total: int
    passed: int
    failed: int
    errors: int
    skipped: int
    failed_tests: tuple[str, ...]
    errored_tests: tuple[str, ...]
    skipped_tests: tuple[str, ...]
    release_blocked: bool

    @classmethod
    def from_suite(cls, result: RegressionSuiteResult) -> "RegressionAssessment":
        return assess_regression_result(result)

    @property
    def successful(self) -> bool:
        return (
            self.status == RegressionStatus.PASSED
            and self.failed == 0
            and self.errors == 0
        )

    @property
    def failure_ids(self) -> tuple[str, ...]:
        return self.failed_tests + self.errored_tests

    def to_dict(self) -> dict[str, Any]:
        return {
            "suite_id": self.suite_id,
            "suite_name": self.suite_name,
            "status": self.status.value,
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
            "skipped": self.skipped,
            "failed_tests": list(self.failed_tests),
            "errored_tests": list(self.errored_tests),
            "skipped_tests": list(self.skipped_tests),
            "release_blocked": self.release_blocked,
        }


def assess_regression_result(
    result: RegressionSuiteResult,
) -> RegressionAssessment:
    failed_tests = tuple(
        item.test_id
        for item in result.results
        if item.status == RegressionStatus.FAILED
    )
    errored_tests = tuple(
        item.test_id
        for item in result.results
        if item.status == RegressionStatus.ERROR
    )
    skipped_tests = tuple(
        item.test_id
        for item in result.results
        if item.status == RegressionStatus.SKIPPED
    )

    return RegressionAssessment(
        suite_id=result.suite_id,
        suite_name=getattr(result, "suite_name", ""),
        status=result.status,
        total=result.total,
        passed=result.passed,
        failed=result.failed,
        errors=result.errors,
        skipped=result.skipped,
        failed_tests=failed_tests,
        errored_tests=errored_tests,
        skipped_tests=skipped_tests,
        release_blocked=bool(failed_tests or errored_tests),
    )


__all__ = ["RegressionAssessment", "assess_regression_result"]
