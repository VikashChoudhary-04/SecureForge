"""Models for SecureForge security regression testing."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    """Return the current UTC timestamp."""
    return datetime.now(UTC)


class RegressionStatus(StrEnum):
    """Execution status of a regression test."""

    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    SKIPPED = "skipped"


class RegressionTest(BaseModel):
    """Definition of a repeatable security regression test."""

    model_config = ConfigDict(extra="allow")

    test_id: str
    name: str

    security_requirement: str

    description: str
    objective: str

    target: str
    method: str = "GET"

    expected_result: str
    failure_condition: str

    enabled: bool = True

    tags: list[str] = Field(
        default_factory=list
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )


class RegressionResult(BaseModel):
    """Result produced by executing a regression test."""

    model_config = ConfigDict(extra="allow")

    test_id: str
    security_requirement: str

    status: RegressionStatus

    expected_result: str
    actual_result: str | None = None

    message: str | None = None

    evidence: dict[str, Any] = Field(
        default_factory=dict
    )

    started_at: datetime = Field(
        default_factory=utc_now
    )

    completed_at: datetime | None = None

    duration_seconds: float | None = None

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )

    @property
    def passed(self) -> bool:
        """Return whether the regression test passed."""
        return self.status == RegressionStatus.PASSED

    @property
    def failed(self) -> bool:
        """Return whether the regression test failed."""
        return self.status == RegressionStatus.FAILED


class RegressionSuite(BaseModel):
    """Collection of security regression tests."""

    model_config = ConfigDict(extra="allow")

    suite_id: str
    name: str

    tests: list[RegressionTest] = Field(
        default_factory=list
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )

    def enabled_tests(self) -> list[RegressionTest]:
        """Return only enabled regression tests."""
        return [
            test
            for test in self.tests
            if test.enabled
        ]


class RegressionSuiteResult(BaseModel):
    """Aggregate result of a regression suite execution."""

    model_config = ConfigDict(extra="allow")

    suite_id: str
    suite_name: str

    status: RegressionStatus

    results: list[RegressionResult] = Field(
        default_factory=list
    )

    started_at: datetime = Field(
        default_factory=utc_now
    )

    completed_at: datetime | None = None

    duration_seconds: float | None = None

    @property
    def total(self) -> int:
        """Return the total number of executed results."""
        return len(self.results)

    @property
    def passed(self) -> int:
        """Return the number of passed tests."""
        return sum(
            result.status == RegressionStatus.PASSED
            for result in self.results
        )

    @property
    def failed(self) -> int:
        """Return the number of failed tests."""
        return sum(
            result.status == RegressionStatus.FAILED
            for result in self.results
        )

    @property
    def errors(self) -> int:
        """Return the number of tests that errored."""
        return sum(
            result.status == RegressionStatus.ERROR
            for result in self.results
        )

    @property
    def skipped(self) -> int:
        """Return the number of skipped tests."""
        return sum(
            result.status == RegressionStatus.SKIPPED
            for result in self.results
        )

    @property
    def successful(self) -> bool:
        """Return whether the suite completed without failures."""
        return (
            self.status == RegressionStatus.PASSED
            and self.failed == 0
            and self.errors == 0
        )


__all__ = [
    "RegressionResult",
    "RegressionStatus",
    "RegressionSuite",
    "RegressionSuiteResult",
    "RegressionTest",
    "utc_now",
]
