"""Execution engine for SecureForge security regression tests."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from time import perf_counter
from typing import Any

from .models import (
RegressionResult,
RegressionStatus,
RegressionSuite,
RegressionSuiteResult,
RegressionTest,
)

def utc_now() -> datetime:
"""Return the current UTC timestamp."""
return datetime.now(timezone.utc)

class RegressionExecutionError(Exception):
"""Raised when regression execution cannot continue."""

RegressionExecutor = Callable[
[RegressionTest],
dict[str, Any],
]

class RegressionEngine:
"""Execute repeatable security regression tests."""

```
def __init__(
    self,
    executor: RegressionExecutor | None = None,
) -> None:
    self.executor = executor

def run_test(
    self,
    test: RegressionTest,
) -> RegressionResult:
    """Execute one regression test."""
    started_at = utc_now()
    timer_started = perf_counter()

    if not test.enabled:
        completed_at = utc_now()

        return RegressionResult(
            test_id=test.test_id,
            security_requirement=(
                test.security_requirement
            ),
            status=RegressionStatus.SKIPPED,
            expected_result=test.expected_result,
            actual_result=None,
            message="Regression test is disabled.",
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=(
                perf_counter()
                - timer_started
            ),
        )

    if self.executor is None:
        completed_at = utc_now()

        return RegressionResult(
            test_id=test.test_id,
            security_requirement=(
                test.security_requirement
            ),
            status=RegressionStatus.ERROR,
            expected_result=test.expected_result,
            actual_result=None,
            message=(
                "No regression executor "
                "has been configured."
            ),
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=(
                perf_counter()
                - timer_started
            ),
        )

    try:
        execution = self.executor(test)

        if not isinstance(
            execution,
            dict,
        ):
            raise RegressionExecutionError(
                "Regression executor must return a mapping."
            )

        status = self._parse_status(
            execution.get("status")
        )

        actual_result = execution.get(
            "actual_result"
        )

        message = execution.get(
            "message"
        )

        evidence = execution.get(
            "evidence",
            {},
        )

        if not isinstance(evidence, dict):
            evidence = {
                "raw": evidence
            }

        metadata = execution.get(
            "metadata",
            {},
        )

        if not isinstance(metadata, dict):
            metadata = {
                "raw": metadata
            }

        completed_at = utc_now()

        return RegressionResult(
            test_id=test.test_id,
            security_requirement=(
                test.security_requirement
            ),
            status=status,
            expected_result=test.expected_result,
            actual_result=(
                str(actual_result)
                if actual_result is not None
                else None
            ),
            message=(
                str(message)
                if message is not None
                else None
            ),
            evidence=evidence,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=(
                perf_counter()
                - timer_started
            ),
            metadata=metadata,
        )

    except Exception as exc:
        completed_at = utc_now()

        return RegressionResult(
            test_id=test.test_id,
            security_requirement=(
                test.security_requirement
            ),
            status=RegressionStatus.ERROR,
            expected_result=test.expected_result,
            actual_result=None,
            message=str(exc),
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=(
                perf_counter()
                - timer_started
            ),
        )

def run_suite(
    self,
    suite: RegressionSuite,
) -> RegressionSuiteResult:
    """Execute all enabled tests in a regression suite."""
    started_at = utc_now()
    timer_started = perf_counter()

    results = [
        self.run_test(test)
        for test in suite.tests
        if test.enabled
    ]

    status = self._suite_status(results)

    completed_at = utc_now()

    return RegressionSuiteResult(
        suite_id=suite.suite_id,
        suite_name=suite.name,
        status=status,
        results=results,
        started_at=started_at,
        completed_at=completed_at,
        duration_seconds=(
            perf_counter()
            - timer_started
        ),
    )

@staticmethod
def _parse_status(
    value: Any,
) -> RegressionStatus:
    """Convert executor status into RegressionStatus."""
    if isinstance(
        value,
        RegressionStatus,
    ):
        return value

    if not isinstance(value, str):
        raise RegressionExecutionError(
            "Regression executor did not return a status."
        )

    normalized = value.strip().lower()

    aliases = {
        "pass": RegressionStatus.PASSED,
        "passed": RegressionStatus.PASSED,
        "success": RegressionStatus.PASSED,
        "fail": RegressionStatus.FAILED,
        "failed": RegressionStatus.FAILED,
        "error": RegressionStatus.ERROR,
        "skipped": RegressionStatus.SKIPPED,
        "skip": RegressionStatus.SKIPPED,
    }

    try:
        return aliases[normalized]
    except KeyError as exc:
        raise RegressionExecutionError(
            f"Unsupported regression status '{value}'."
        ) from exc

@staticmethod
def _suite_status(
    results: list[RegressionResult],
) -> RegressionStatus:
    """Determine the aggregate suite status."""
    if not results:
        return RegressionStatus.SKIPPED

    if any(
        result.status == RegressionStatus.ERROR
        for result in results
    ):
        return RegressionStatus.ERROR

    if any(
        result.status == RegressionStatus.FAILED
        for result in results
    ):
        return RegressionStatus.FAILED

    if all(
        result.status == RegressionStatus.SKIPPED
        for result in results
    ):
        return RegressionStatus.SKIPPED

    return RegressionStatus.PASSED
```
