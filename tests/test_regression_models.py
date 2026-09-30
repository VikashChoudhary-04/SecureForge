"""Tests for SecureForge regression models."""

from __future__ import annotations

from datetime import timezone

from secureforge.regression import (
    RegressionResult,
    RegressionStatus,
    RegressionSuite,
    RegressionSuiteResult,
    RegressionTest,
)


def build_test(
    *,
    test_id: str = "BOLA-001",
    enabled: bool = True,
) -> RegressionTest:
    """Build a representative regression test."""
    return RegressionTest(
        test_id=test_id,
        name="BOLA Authorization Regression",
        security_requirement="SF-AUTHZ-001",
        description=(
            "Verify that a user cannot access "
            "another user's order."
        ),
        objective=(
            "Prevent broken object-level authorization "
            "from returning unauthorized data."
        ),
        target="/api/orders/2",
        method="GET",
        expected_result="HTTP 403",
        failure_condition=(
            "The response returns another user's order."
        ),
        enabled=enabled,
        tags=[
            "authorization",
            "bola",
            "api",
        ],
    )


def test_regression_test_contains_security_requirement():
    """Regression tests should map to a security requirement."""
    test = build_test()

    assert test.test_id == "BOLA-001"
    assert test.security_requirement == (
        "SF-AUTHZ-001"
    )
    assert test.target == "/api/orders/2"
    assert test.method == "GET"
    assert test.expected_result == "HTTP 403"


def test_regression_test_can_be_disabled():
    """Regression tests should support explicit disabling."""
    test = build_test(
        enabled=False
    )

    assert test.enabled is False


def test_regression_result_passed_property():
    """Passed results should report passed=True."""
    result = RegressionResult(
        test_id="BOLA-001",
        security_requirement="SF-AUTHZ-001",
        status=RegressionStatus.PASSED,
        expected_result="HTTP 403",
        actual_result="HTTP 403",
        message="Authorization correctly denied.",
    )

    assert result.passed is True
    assert result.failed is False


def test_regression_result_failed_property():
    """Failed results should report failed=True."""
    result = RegressionResult(
        test_id="BOLA-001",
        security_requirement="SF-AUTHZ-001",
        status=RegressionStatus.FAILED,
        expected_result="HTTP 403",
        actual_result="HTTP 200",
        message="Authorization bypass remains.",
    )

    assert result.passed is False
    assert result.failed is True


def test_regression_result_timestamp_is_utc():
    """Regression result timestamps should use UTC."""
    result = RegressionResult(
        test_id="SQLI-001",
        security_requirement="SF-INPUT-001",
        status=RegressionStatus.PASSED,
        expected_result="Parameterized query",
    )

    assert result.started_at.tzinfo == timezone.utc


def test_regression_suite_returns_enabled_tests():
    """Suite should expose only enabled tests when requested."""
    suite = RegressionSuite(
        suite_id="securecommerce-regression",
        name="SecureCommerce Security Regression Suite",
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

    enabled = suite.enabled_tests()

    assert [
        test.test_id
        for test in enabled
    ] == [
        "BOLA-001",
        "XSS-001",
    ]


def test_suite_result_counts_passed_failed_error_skipped():
    """Suite result should correctly count each execution state."""
    suite_result = RegressionSuiteResult(
        suite_id="securecommerce-regression",
        suite_name="SecureCommerce Security Regression Suite",
        status=RegressionStatus.FAILED,
        results=[
            RegressionResult(
                test_id="BOLA-001",
                security_requirement="SF-AUTHZ-001",
                status=RegressionStatus.PASSED,
                expected_result="HTTP 403",
            ),
            RegressionResult(
                test_id="SQLI-001",
                security_requirement="SF-INPUT-001",
                status=RegressionStatus.FAILED,
                expected_result="No SQL injection",
            ),
            RegressionResult(
                test_id="SECRET-001",
                security_requirement="SF-SECRET-001",
                status=RegressionStatus.ERROR,
                expected_result="No hardcoded secret",
            ),
            RegressionResult(
                test_id="NMAP-001",
                security_requirement="SF-API-001",
                status=RegressionStatus.SKIPPED,
                expected_result="No unexpected service",
            ),
        ],
    )

    assert suite_result.total == 4
    assert suite_result.passed == 1
    assert suite_result.failed == 1
    assert suite_result.errors == 1
    assert suite_result.skipped == 1


def test_suite_result_is_not_successful_when_test_fails():
    """A failed regression test should make the suite unsuccessful."""
    suite_result = RegressionSuiteResult(
        suite_id="securecommerce-regression",
        suite_name="SecureCommerce Security Regression Suite",
        status=RegressionStatus.FAILED,
        results=[
            RegressionResult(
                test_id="BOLA-001",
                security_requirement="SF-AUTHZ-001",
                status=RegressionStatus.FAILED,
                expected_result="HTTP 403",
                actual_result="HTTP 200",
            )
        ],
    )

    assert suite_result.successful is False


def test_suite_result_is_not_successful_when_test_errors():
    """A regression execution error should make the suite unsuccessful."""
    suite_result = RegressionSuiteResult(
        suite_id="securecommerce-regression",
        suite_name="SecureCommerce Security Regression Suite",
        status=RegressionStatus.ERROR,
        results=[
            RegressionResult(
                test_id="BOLA-001",
                security_requirement="SF-AUTHZ-001",
                status=RegressionStatus.ERROR,
                expected_result="HTTP 403",
                message="Executor unavailable.",
            )
        ],
    )

    assert suite_result.successful is False


def test_suite_result_is_successful_when_all_tests_pass():
    """A suite with only passing tests should be successful."""
    suite_result = RegressionSuiteResult(
        suite_id="securecommerce-regression",
        suite_name="SecureCommerce Security Regression Suite",
        status=RegressionStatus.PASSED,
        results=[
            RegressionResult(
                test_id="BOLA-001",
                security_requirement="SF-AUTHZ-001",
                status=RegressionStatus.PASSED,
                expected_result="HTTP 403",
                actual_result="HTTP 403",
            ),
            RegressionResult(
                test_id="SQLI-001",
                security_requirement="SF-INPUT-001",
                status=RegressionStatus.PASSED,
                expected_result="No SQL injection",
                actual_result="No SQL injection",
            ),
        ],
    )

    assert suite_result.successful is True
    assert suite_result.passed == 2
    assert suite_result.failed == 0
    assert suite_result.errors == 0
