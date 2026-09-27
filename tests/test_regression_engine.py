"""Tests for the SecureForge regression execution engine."""

from **future** import annotations

from secureforge.regression import (
RegressionEngine,
RegressionStatus,
RegressionSuite,
RegressionTest,
)

def build_test(
test_id: str = "BOLA-001",
enabled: bool = True,
) -> RegressionTest:
"""Build a representative regression test."""
return RegressionTest(
test_id=test_id,
name=f"Regression {test_id}",
security_requirement="SF-AUTHZ-001",
description="Verify authorization behavior.",
objective="Prevent authorization regression.",
target="/api/orders/2",
method="GET",
expected_result="HTTP 403",
failure_condition="HTTP 200 exposes unauthorized data.",
enabled=enabled,
)

def test_engine_records_passed_test():
"""A successful executor result should produce PASSED."""
def executor(test):
return {
"status": "passed",
"actual_result": "HTTP 403",
"message": "Authorization correctly denied.",
"evidence": {
"status_code": 403,
},
}

```
result = RegressionEngine(
    executor=executor
).run_test(
    build_test()
)

assert result.status == RegressionStatus.PASSED
assert result.passed is True
assert result.failed is False
assert result.actual_result == "HTTP 403"
assert result.evidence == {
    "status_code": 403,
}
assert result.completed_at is not None
assert result.duration_seconds is not None
```

def test_engine_records_failed_test():
"""A failed executor result should produce FAILED."""
def executor(test):
return {
"status": "failed",
"actual_result": "HTTP 200",
"message": "Authorization bypass remains.",
"evidence": {
"status_code": 200,
},
}

```
result = RegressionEngine(
    executor=executor
).run_test(
    build_test()
)

assert result.status == RegressionStatus.FAILED
assert result.passed is False
assert result.failed is True
assert result.actual_result == "HTTP 200"
assert result.message == (
    "Authorization bypass remains."
)
```

def test_engine_records_executor_error():
"""Executor exceptions should become ERROR results."""
def executor(test):
raise RuntimeError(
"Target application unavailable."
)

```
result = RegressionEngine(
    executor=executor
).run_test(
    build_test()
)

assert result.status == RegressionStatus.ERROR
assert result.actual_result is None
assert result.message == (
    "Target application unavailable."
)
```

def test_engine_errors_when_no_executor_is_configured():
"""Missing executor should produce an ERROR result."""
result = RegressionEngine().run_test(
build_test()
)

```
assert result.status == RegressionStatus.ERROR
assert "No regression executor" in (
    result.message or ""
)
```

def test_engine_skips_disabled_test():
"""Disabled tests should be reported as SKIPPED."""
def executor(test):
raise AssertionError(
"Disabled test must not execute."
)

```
result = RegressionEngine(
    executor=executor
).run_test(
    build_test(
        enabled=False
    )
)

assert result.status == RegressionStatus.SKIPPED
assert result.message == (
    "Regression test is disabled."
)
```

def test_engine_accepts_status_aliases():
"""Common status aliases should normalize correctly."""
statuses = [
(
"pass",
RegressionStatus.PASSED,
),
(
"success",
RegressionStatus.PASSED,
),
(
"fail",
RegressionStatus.FAILED,
),
(
"error",
RegressionStatus.ERROR,
),
(
"skip",
RegressionStatus.SKIPPED,
),
]

```
for raw_status, expected_status in statuses:
    result = RegressionEngine(
        executor=lambda test, status=raw_status: {
            "status": status,
            "actual_result": "test",
        }
    ).run_test(
        build_test()
    )

    assert result.status == expected_status
```

def test_engine_rejects_invalid_executor_status():
"""Unknown executor statuses should become ERROR."""
result = RegressionEngine(
executor=lambda test: {
"status": "unknown-status",
}
).run_test(
build_test()
)

```
assert result.status == RegressionStatus.ERROR
assert "Unsupported regression status" in (
    result.message or ""
)
```

def test_engine_requires_mapping_from_executor():
"""Executor output must be a mapping."""
result = RegressionEngine(
executor=lambda test: "invalid"
).run_test(
build_test()
)

```
assert result.status == RegressionStatus.ERROR
assert "must return a mapping" in (
    result.message or ""
)
```

def test_engine_normalizes_non_mapping_evidence():
"""Non-mapping evidence should be safely preserved as raw data."""
result = RegressionEngine(
executor=lambda test: {
"status": "passed",
"actual_result": "HTTP 403",
"evidence": "HTTP 403 response",
}
).run_test(
build_test()
)

```
assert result.status == RegressionStatus.PASSED
assert result.evidence == {
    "raw": "HTTP 403 response"
}
```

def test_engine_runs_only_enabled_suite_tests():
"""Suite execution should not invoke disabled tests."""
executed: list[str] = []

```
def executor(test):
    executed.append(test.test_id)

    return {
        "status": "passed",
        "actual_result": "secure",
    }

suite = RegressionSuite(
    suite_id="securecommerce-regression",
    name="SecureCommerce Regression Suite",
    tests=[
        build_test(
            test_id="BOLA-001",
            enabled=True,
        ),
        build_test(
            test_id="SQLI-001",
            enabled=False,
        ),
        build_test(
            test_id="XSS-001",
            enabled=True,
        ),
    ],
)

result = RegressionEngine(
    executor=executor
).run_suite(
    suite
)

assert executed == [
    "BOLA-001",
    "XSS-001",
]

assert result.status == RegressionStatus.PASSED
assert result.total == 2
assert result.passed == 2
assert result.failed == 0
assert result.errors == 0
```

def test_engine_marks_suite_failed_when_any_test_fails():
"""One failed test should fail the complete suite."""
def executor(test):
if test.test_id == "BOLA-001":
return {
"status": "failed",
"actual_result": "HTTP 200",
}

```
    return {
        "status": "passed",
        "actual_result": "secure",
    }

suite = RegressionSuite(
    suite_id="securecommerce-regression",
    name="SecureCommerce Regression Suite",
    tests=[
        build_test("BOLA-001"),
        build_test("XSS-001"),
    ],
)

result = RegressionEngine(
    executor=executor
).run_suite(
    suite
)

assert result.status == RegressionStatus.FAILED
assert result.total == 2
assert result.passed == 1
assert result.failed == 1
assert result.successful is False
```

def test_engine_marks_suite_error_when_any_test_errors():
"""An execution error should make the suite ERROR."""
def executor(test):
if test.test_id == "BOLA-001":
raise RuntimeError(
"Target unavailable."
)

```
    return {
        "status": "passed",
        "actual_result": "secure",
    }

suite = RegressionSuite(
    suite_id="securecommerce-regression",
    name="SecureCommerce Regression Suite",
    tests=[
        build_test("BOLA-001"),
        build_test("XSS-001"),
    ],
)

result = RegressionEngine(
    executor=executor
).run_suite(
    suite
)

assert result.status == RegressionStatus.ERROR
assert result.errors == 1
assert result.passed == 1
assert result.successful is False
```

def test_engine_marks_empty_suite_skipped():
"""A suite without enabled tests should be skipped."""
suite = RegressionSuite(
suite_id="empty-suite",
name="Empty Regression Suite",
tests=[],
)

```
result = RegressionEngine(
    executor=lambda test: {
        "status": "passed"
    }
).run_suite(
    suite
)

assert result.status == RegressionStatus.SKIPPED
assert result.total == 0
assert result.skipped == 0
assert result.successful is False
```
