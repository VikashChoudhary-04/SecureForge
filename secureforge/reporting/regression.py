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
            expected=getattr(item, "expected", ""),
            actual=getattr(item, "actual", ""),
            message=getattr(item, "message", ""),
            evidence=getattr(item, "evidence", {}),
        )
        for item in result.results
    ]

    return RegressionReport(
        suite_id=result.suite_id,
        suite_name=result.name,
        status=getattr(result.status, "value", result.status),
        total=result.total,
        passed=result.passed,
        failed=result.failed,
        errors=result.errors,
        skipped=result.skipped,
        tests=tests,
        started_at=_text(result.started_at),
        completed_at=_text(result.completed_at),
        duration_seconds=(
            float(result.duration_seconds)
            if result.duration_seconds is not None
            else 0.0
        ),
    )


__all__ = ["build_regression_report"]
