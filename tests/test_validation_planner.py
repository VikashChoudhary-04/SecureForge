```python
# SecureForge validation planner tests

from __future__ import annotations

from secureforge.core.findings.models import (
    Confidence,
    Finding,
    Severity,
)
from secureforge.validation.models import (
    ValidationMethod,
)
from secureforge.validation.planner import (
    ValidationPlanner,
)


def make_finding(
    finding_id: str,
    *,
    endpoint: str | None = None,
    parameter: str | None = None,
) -> Finding:
    """Create a controlled finding for planner tests."""
    return Finding(
        finding_id=finding_id,
        title=f"Test finding {finding_id}",
        source="test",
        asset="SecureCommerce",
        application="SecureCommerce",
        endpoint=endpoint,
        parameter=parameter,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="Controlled planner test finding.",
        impact="Controlled test impact.",
        remediation="Apply the documented remediation.",
    )


def test_securecommerce_finding_can_use_default_endpoint():
    planner = ValidationPlanner()

    finding = make_finding(
        "BOLA-001"
    )

    request = planner.plan_finding(
        finding,
        target="http://localhost:5000",
        method=ValidationMethod.HTTP,
    )

    assert request is not None
    assert request.finding_id == "BOLA-001"
    assert request.endpoint is None
    assert request.target == "http://localhost:5000"


def test_finding_with_explicit_endpoint_preserves_endpoint():
    planner = ValidationPlanner()

    finding = make_finding(
        "SQLI-001",
        endpoint="/vulnerable/search",
        parameter="q",
    )

    request = planner.plan_finding(
        finding,
        target="http://localhost:5000",
    )

    assert request is not None
    assert request.endpoint == "/vulnerable/search"
    assert request.parameter == "q"


def test_unknown_http_finding_without_endpoint_is_skipped():
    planner = ValidationPlanner()

    finding = make_finding(
        "UNKNOWN-001"
    )

    plan = planner.plan(
        [finding],
        target="http://localhost:5000",
        method=ValidationMethod.HTTP,
    )

    assert plan.requests == ()
    assert plan.skipped_findings == (
        "UNKNOWN-001",
    )


def test_multiple_findings_are_planned_and_skipped_correctly():
    planner = ValidationPlanner()

    findings = [
        make_finding("BOLA-001"),
        make_finding(
            "XSS-001",
            endpoint="/vulnerable/search",
            parameter="q",
        ),
        make_finding("UNKNOWN-001"),
    ]

    plan = planner.plan(
        findings,
        target="http://localhost:5000",
    )

    assert len(plan.requests) == 2

    assert {
        request.finding_id
        for request in plan.requests
    } == {
        "BOLA-001",
        "XSS-001",
    }

    assert plan.skipped_findings == (
        "UNKNOWN-001",
    )


def test_empty_target_skips_finding():
    planner = ValidationPlanner()

    finding = make_finding(
        "BOLA-001"
    )

    request = planner.plan_finding(
        finding,
        target="   ",
    )

    assert request is None


def test_empty_finding_id_is_skipped():
    planner = ValidationPlanner()

    finding = make_finding(
        " "
    )

    request = planner.plan_finding(
        finding,
        target="http://localhost:5000",
    )

    assert request is None


def test_explicit_validation_payload_is_used():
    planner = ValidationPlanner()

    finding = make_finding(
        "SQLI-001",
        endpoint="/vulnerable/search",
        parameter="q",
    )

    finding.evidence.append(
        {
            "metadata": {
                "validation_payload": (
                    "' OR '1'='1"
                )
            }
        }
    )

    request = planner.plan_finding(
        finding,
        target="http://localhost:5000",
    )

    assert request is not None
    assert request.payload == (
        "' OR '1'='1"
    )


def test_generic_evidence_is_not_used_as_payload():
    planner = ValidationPlanner()

    finding = make_finding(
        "SQLI-001",
        endpoint="/vulnerable/search",
        parameter="q",
    )

    finding.evidence.append(
        {
            "request": (
                "GET /vulnerable/search?q=test "
                "HTTP/1.1"
            )
        }
    )

    request = planner.plan_finding(
        finding,
        target="http://localhost:5000",
    )

    assert request is not None
    assert request.payload is None
```
