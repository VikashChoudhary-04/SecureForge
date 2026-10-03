"""Focused tests for SecureForge policy exception safety."""

from datetime import datetime, timedelta, timezone

from secureforge.core.findings import Finding, Severity
from secureforge.core.policy import (
    PolicyConfig,
    PolicyException,
)
from secureforge.core.policy.evaluator import PolicyEvaluator


def build_finding(
    finding_id: str = "SF-001",
    *,
    security_requirement: str | None = "SF-AUTHZ-001",
) -> Finding:
    """Create a representative finding."""
    return Finding(
        finding_id=finding_id,
        title="Broken Object Level Authorization",
        source="dast",
        application="SecureCommerce",
        asset="securecommerce-api",
        endpoint="/api/orders/123",
        parameter="id",
        cwe="CWE-639",
        owasp="API1",
        security_requirement=security_requirement,
        severity=Severity.HIGH,
        description="Authorization bypass was confirmed.",
        impact="Users may access unauthorized objects.",
        remediation="Enforce object-level authorization.",
    )


def build_policy(
    exceptions: list[PolicyException],
) -> PolicyConfig:
    """Create a policy containing the supplied exceptions."""
    return PolicyConfig(
        policy_id="test-policy",
        version="1.0",
        exceptions=exceptions,
    )


def future_timestamp() -> str:
    """Return an ISO timestamp safely in the future."""
    return (
        datetime.now(timezone.utc)
        + timedelta(days=1)
    ).isoformat()


def past_timestamp() -> str:
    """Return an ISO timestamp safely in the past."""
    return (
        datetime.now(timezone.utc)
        - timedelta(days=1)
    ).isoformat()


def test_future_exception_applies() -> None:
    """Verify a non-expired exception can apply."""
    finding = build_finding()

    exception = PolicyException(
        exception_id="EXC-FUTURE",
        finding_id="SF-001",
        reason="Temporary approved exception.",
        expires_at=future_timestamp(),
    )

    result = PolicyEvaluator.find_exception(
        finding,
        build_policy([exception]),
    )

    assert result is not None
    assert result.exception_id == "EXC-FUTURE"


def test_expired_exception_does_not_apply() -> None:
    """Verify an expired exception cannot bypass policy."""
    finding = build_finding()

    exception = PolicyException(
        exception_id="EXC-EXPIRED",
        finding_id="SF-001",
        reason="Expired exception.",
        expires_at=past_timestamp(),
    )

    result = PolicyEvaluator.find_exception(
        finding,
        build_policy([exception]),
    )

    assert result is None


def test_malformed_expiration_does_not_apply() -> None:
    """Verify an invalid expiration cannot activate an exception."""
    finding = build_finding()

    exception = PolicyException(
        exception_id="EXC-INVALID-DATE",
        finding_id="SF-001",
        reason="Invalid expiration.",
        expires_at="not-a-timestamp",
    )

    result = PolicyEvaluator.find_exception(
        finding,
        build_policy([exception]),
    )

    assert result is None


def test_exception_without_expiration_remains_supported() -> None:
    """Verify existing non-expiring exceptions remain supported."""
    finding = build_finding()

    exception = PolicyException(
        exception_id="EXC-NO-EXPIRY",
        finding_id="SF-001",
        reason="Approved exception without expiration.",
    )

    result = PolicyEvaluator.find_exception(
        finding,
        build_policy([exception]),
    )

    assert result is not None
    assert result.exception_id == "EXC-NO-EXPIRY"


def test_first_matching_exception_wins() -> None:
    """Verify the first matching exception is returned."""
    finding = build_finding(
        finding_id="SF-001",
        security_requirement="SF-AUTHZ-001",
    )

    first_exception = PolicyException(
        exception_id="EXC-FIRST",
        requirement_id="SF-AUTHZ-001",
        reason="First matching exception.",
    )

    second_exception = PolicyException(
        exception_id="EXC-SECOND",
        finding_id="SF-001",
        reason="Second matching exception.",
    )

    result = PolicyEvaluator.find_exception(
        finding,
        build_policy(
            [
                first_exception,
                second_exception,
            ]
        ),
    )

    assert result is not None
    assert result.exception_id == "EXC-FIRST"


def test_disabled_expired_and_unrelated_exceptions_are_skipped() -> None:
    """Verify inactive exceptions cannot become bypasses."""
    finding = build_finding()

    exceptions = [
        PolicyException(
            exception_id="EXC-DISABLED",
            finding_id="SF-001",
            reason="Disabled exception.",
            enabled=False,
        ),
        PolicyException(
            exception_id="EXC-EXPIRED",
            finding_id="SF-001",
            reason="Expired exception.",
            expires_at=past_timestamp(),
        ),
        PolicyException(
            exception_id="EXC-UNRELATED",
            finding_id="SF-999",
            reason="Unrelated exception.",
        ),
    ]

    result = PolicyEvaluator.find_exception(
        finding,
        build_policy(exceptions),
    )

    assert result is None


def test_unscoped_exception_does_not_apply() -> None:
    """Verify an exception without a matching scope cannot apply."""
    finding = build_finding()

    exception = PolicyException(
        exception_id="EXC-UNSCOPED",
        reason="Exception without an explicit scope.",
    )

    result = PolicyEvaluator.find_exception(
        finding,
        build_policy([exception]),
    )

    assert result is None
