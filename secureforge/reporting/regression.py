"""Regression reporting adapters for SecureForge."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from secureforge.regression import RegressionSuiteResult
from .models import RegressionReport, RegressionTestReport


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def build_regression_report(result: RegressionSuiteResult) -> RegressionReport:
    tests = [
        RegressionTestReport(
            test_id=item.test_id,
            status=getattr(item.status, "value", item.status),
            expected=getattr(item, "expected", getattr(item, "expected_result", "")),
            actual=getattr(item, "actual", getattr(item, "actual_result", "")) or "",
            message=getattr(item, "message", "") or "",
            evidence=dict(getattr(item, "evidence", {}) or {}),
        )
        for item in result.results
    ]
    return RegressionReport(
        suite_id=result.suite_id,
        suite_name=getattr(result, "name", "") or getattr(result, "suite_name", "") or result.suite_id,
        status=getattr(result.status, "value", result.status),
        total=result.total,
        passed=result.passed,
        failed=result.failed,
        errors=result.errors,
        errored=result.errors,
        skipped=result.skipped,
        tests=tests,
        started_at=_text(result.started_at),
        completed_at=_text(result.completed_at),
        duration_seconds=float(result.duration_seconds or 0.0),
        tests_total=result.total,
        tests_failed=result.failed,
    )

__all__ = ["build_regression_report"]
