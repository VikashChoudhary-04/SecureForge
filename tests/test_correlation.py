"""Tests for SecureForge finding correlation."""

from secureforge.core.correlation import (
    CorrelationConfidence,
    CorrelationEngine,
    CorrelationType,
)
from secureforge.core.findings import (
    Confidence,
    Evidence,
    Finding,
    Severity,
)


def build_finding(
    *,
    finding_id: str,
    source: str,
    title: str = "SQL Injection",
    endpoint: str = "/api/products",
    parameter: str = "search",
    cwe: str = "CWE-89",
    asset: str = "securecommerce-api",
) -> Finding:
    """Create a representative finding for correlation tests."""
    return Finding(
        finding_id=finding_id,
        title=title,
        source=source,
        application="SecureCommerce",
        asset=asset,
        endpoint=endpoint,
        parameter=parameter,
        cwe=cwe,
        owasp="A03",
        security_requirement="SF-INPUT-001",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="A SQL injection vulnerability was detected.",
        impact="An attacker may manipulate database queries.",
        remediation="Use parameterized database queries.",
    )


def test_findings_with_multiple_matching_signals_are_correlated() -> None:
    """Verify strong matching signals create a correlation."""
    first = build_finding(
        finding_id="SF-0001",
        source="sast",
    )
    second = build_finding(
        finding_id="SF-0002",
        source="dast",
    )

    engine = CorrelationEngine()

    results = engine.correlate(
        [first, second]
    )

    assert len(results) == 1

    correlated = results[0]

    assert correlated.source_finding_ids == [
        "SF-0001",
        "SF-0002",
    ]
    assert correlated.source_count == 2
    assert correlated.confidence == CorrelationConfidence.HIGH


def test_same_cwe_and_asset_are_strong_correlation_signals() -> None:
    """Verify CWE and asset matching are recorded as signals."""
    first = build_finding(
        finding_id="SF-0001",
        source="sast",
    )
    second = build_finding(
        finding_id="SF-0002",
        source="burp",
    )

    engine = CorrelationEngine()

    results = engine.correlate(
        [first, second]
    )

    assert len(results) == 1

    link = results[0].correlation_links[0]

    assert "same_cwe" in link.signals
    assert "same_asset" in link.signals
    assert link.correlation_type == CorrelationType.SAME_VULNERABILITY


def test_same_endpoint_is_used_for_correlation() -> None:
    """Verify endpoint matching contributes to correlation."""
    first = build_finding(
        finding_id="SF-0001",
        source="dast",
        cwe="CWE-79",
        title="Cross Site Scripting",
    )
    second = build_finding(
        finding_id="SF-0002",
        source="burp",
        cwe="CWE-79",
        title="Cross Site Scripting",
    )

    engine = CorrelationEngine()

    results = engine.correlate(
        [first, second]
    )

    assert len(results) == 1

    link = results[0].correlation_links[0]

    assert "same_endpoint" in link.signals


def test_different_findings_without_enough_signals_are_not_correlated() -> None:
    """Verify weakly related findings remain independent."""
    first = build_finding(
        finding_id="SF-0001",
        source="sast",
        title="SQL Injection",
        endpoint="/api/products",
        parameter="search",
        cwe="CWE-89",
        asset="backend-a",
    )
    second = build_finding(
        finding_id="SF-0002",
        source="dast",
        title="Cross Site Scripting",
        endpoint="/api/profile",
        parameter="name",
        cwe="CWE-79",
        asset="backend-b",
    )

    engine = CorrelationEngine()

    results = engine.correlate(
        [first, second]
    )

    assert results == []


def test_endpoint_query_strings_are_normalized() -> None:
    """Verify equivalent endpoints with query strings correlate."""
    first = build_finding(
        finding_id="SF-0001",
        source="dast",
        endpoint="/api/products?search=test",
    )
    second = build_finding(
        finding_id="SF-0002",
        source="burp",
        endpoint="/api/products?search=admin",
    )

    engine = CorrelationEngine()

    results = engine.correlate(
        [first, second]
    )

    assert len(results) == 1

    link = results[0].correlation_links[0]

    assert "same_endpoint" in link.signals


def test_correlated_finding_collects_evidence_ids() -> None:
    """Verify evidence from both findings is represented."""
    first = build_finding(
        finding_id="SF-0001",
        source="sast",
    )
    second = build_finding(
        finding_id="SF-0002",
        source="dast",
    )

    first.add_evidence(
        Evidence(
            evidence_id="E-SAST-001",
            source="sast",
            description=(
                "Static analysis identified unsafe SQL construction."
            ),
        )
    )

    second.add_evidence(
        Evidence(
            evidence_id="E-DAST-001",
            source="dast",
            description=(
                "Dynamic testing confirmed SQL injection."
            ),
        )
    )

    engine = CorrelationEngine()

    results = engine.correlate(
        [first, second]
    )

    assert len(results) == 1

    correlated = results[0]

    assert correlated.evidence_count == 2
    assert "E-SAST-001" in correlated.evidence_ids
    assert "E-DAST-001" in correlated.evidence_ids


def test_single_finding_does_not_create_correlation() -> None:
    """Verify correlation requires at least two findings."""
    finding = build_finding(
        finding_id="SF-0001",
        source="dast",
    )

    engine = CorrelationEngine()

    results = engine.correlate(
        [finding]
    )

    assert results == []


def test_minimum_signals_can_be_configured() -> None:
    """Verify correlation sensitivity can be configured."""
    first = build_finding(
        finding_id="SF-0001",
        source="sast",
    )
    second = build_finding(
        finding_id="SF-0002",
        source="dast",
    )

    engine = CorrelationEngine(
        minimum_signals=4
    )

    results = engine.correlate(
        [first, second]
    )

    assert results == []


def test_correlated_id_is_deterministic() -> None:
    """Verify correlation IDs do not depend on input ordering."""
    first = build_finding(
        finding_id="SF-0001",
        source="sast",
    )
    second = build_finding(
        finding_id="SF-0002",
        source="dast",
    )

    engine = CorrelationEngine()

    first_result = engine.correlate(
        [first, second]
    )
    second_result = engine.correlate(
        [second, first]
    )

    assert (
        first_result[0].finding_id
        == second_result[0].finding_id
    )
