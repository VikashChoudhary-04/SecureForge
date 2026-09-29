"""Integration tests for the SecureForge core security pipeline."""

from secureforge.core.correlation import CorrelationEngine
from secureforge.core.findings import (
    Confidence,
    Evidence,
    Finding,
    Severity,
)
from secureforge.core.policy import (
    PolicyAction,
    PolicyConfig,
    PolicyEngine,
    PolicyRule,
)
from secureforge.core.release_gate import (
    ReleaseDecision,
    ReleaseGateEngine,
    ReleaseGateInput,
)
from secureforge.core.risk import (
    AssetImportance,
    Environment,
    RiskContext,
    RiskEngine,
)


def build_finding(
    *,
    finding_id: str,
    source: str,
    title: str,
    severity: Severity,
    endpoint: str,
    parameter: str,
    cwe: str,
) -> Finding:
    """Create a representative SecureCommerce finding."""
    return Finding(
        finding_id=finding_id,
        title=title,
        source=source,
        application="SecureCommerce",
        asset="securecommerce-api",
        endpoint=endpoint,
        parameter=parameter,
        cwe=cwe,
        owasp="API1",
        security_requirement="SF-AUTHZ-001",
        severity=severity,
        confidence=Confidence.HIGH,
        description=(
            "A controlled security finding for integration testing."
        ),
        impact=(
            "The affected security control may be bypassed."
        ),
        remediation=(
            "Apply the documented security remediation."
        ),
    )


def test_core_pipeline_blocks_high_risk_security_issue() -> None:
    """Verify a high-risk finding flows through the complete pipeline."""
    sast_finding = build_finding(
        finding_id="SF-SAST-001",
        source="sast",
        title="Broken Object Level Authorization",
        severity=Severity.HIGH,
        endpoint="/api/orders/1002",
        parameter="id",
        cwe="CWE-639",
    )

    dast_finding = build_finding(
        finding_id="SF-DAST-001",
        source="dast",
        title="Broken Object Level Authorization",
        severity=Severity.HIGH,
        endpoint="/api/orders/1002",
        parameter="id",
        cwe="CWE-639",
    )

    sast_finding.add_evidence(
        Evidence(
            evidence_id="E-SAST-001",
            source="sast",
            description=(
                "Static analysis identified missing object authorization."
            ),
        )
    )

    dast_finding.add_evidence(
        Evidence(
            evidence_id="E-DAST-001",
            source="dast",
            description=(
                "Dynamic testing accessed another user's order."
            ),
        )
    )

    findings = [
        sast_finding,
        dast_finding,
    ]

    correlations = CorrelationEngine().correlate(
        findings
    )

    assert len(correlations) == 1
    assert correlations[0].source_count == 2
    assert correlations[0].evidence_count == 2

    risk_engine = RiskEngine()

    assessments = [
        risk_engine.evaluate(
            finding,
            RiskContext(
                asset_importance=AssetImportance.HIGH,
                internet_exposed=True,
                authentication_required=False,
                sensitive_data=True,
                exploit_evidence=True,
                environment=Environment.STAGING,
            ),
        )
        for finding in findings
    ]

    assert all(
        assessment.risk_score >= 70
        for assessment in assessments
    )

    policy = PolicyConfig(
        policy_id="integration-policy",
        version="1.0",
        rules=[
            PolicyRule(
                rule_id="BLOCK-HIGH",
                name="Block high findings",
                description=(
                    "High severity findings block release."
                ),
                severity="high",
                action=PolicyAction.BLOCK,
            ),
        ],
    )

    policy_result = PolicyEngine().evaluate(
        findings,
        assessments,
        policy,
    )

    assert policy_result.decision.value == "block"
    assert len(
        policy_result.blocking_findings
    ) == 2

    gate_input = ReleaseGateInput(
        application="SecureCommerce",
        version="1.0.0",
        commit_sha="integration-test-sha",
        policy_decision=ReleaseDecision(
            policy_result.decision.value
        ),
        blocking_findings=(
            policy_result.blocking_findings
        ),
        review_findings=(
            policy_result.review_findings
        ),
        exceptions_applied=(
            policy_result.exceptions_applied
        ),
    )

    release_result = ReleaseGateEngine().evaluate(
        gate_input
    )

    assert release_result.decision == ReleaseDecision.BLOCK
    assert release_result.is_blocked is True
    assert release_result.blocking_findings == [
        "SF-SAST-001",
        "SF-DAST-001",
    ]


def test_core_pipeline_allows_low_risk_finding() -> None:
    """Verify an explicitly permitted low-risk finding can pass."""
    finding = build_finding(
        finding_id="SF-LOW-001",
        source="sast",
        title="Informational Configuration Observation",
        severity=Severity.LOW,
        endpoint="/health",
        parameter="",
        cwe="CWE-16",
    )

    risk = RiskEngine().evaluate(
        finding,
        RiskContext(
            asset_importance=AssetImportance.LOW,
            internet_exposed=False,
            authentication_required=True,
            sensitive_data=False,
            exploit_evidence=False,
            environment=Environment.TEST,
        ),
    )

    assert risk.risk_score < 40
    assert risk.contextual_risk.value in {
        "info",
        "low",
    }

    policy = PolicyConfig(
        policy_id="low-risk-policy",
        version="1.0",
        rules=[
            PolicyRule(
                rule_id="PASS-LOW",
                name="Pass low findings",
                description=(
                    "Low severity findings are permitted."
                ),
                severity="low",
                action=PolicyAction.PASS,
            ),
        ],
    )

    policy_result = PolicyEngine().evaluate(
        [finding],
        [risk],
        policy,
    )

    assert policy_result.decision.value == "pass"
    assert policy_result.passed_findings == [
        "SF-LOW-001"
    ]

    gate_input = ReleaseGateInput(
        application="SecureCommerce",
        version="1.0.0",
        commit_sha="pass-test-sha",
        policy_decision=ReleaseDecision(
            policy_result.decision.value
        ),
        blocking_findings=(
            policy_result.blocking_findings
        ),
        review_findings=(
            policy_result.review_findings
        ),
        exceptions_applied=(
            policy_result.exceptions_applied
        ),
    )

    release_result = ReleaseGateEngine().evaluate(
        gate_input
    )

    assert release_result.decision == ReleaseDecision.PASS
    assert release_result.passed is True


def test_failed_regression_overrides_passing_policy() -> None:
    """Verify a regression failure prevents an otherwise passing release."""
    finding = build_finding(
        finding_id="SF-LOW-002",
        source="sast",
        title="Low Risk Finding",
        severity=Severity.LOW,
        endpoint="/health",
        parameter="",
        cwe="CWE-16",
    )

    risk = RiskEngine().evaluate(
        finding,
        RiskContext(
            asset_importance=AssetImportance.LOW,
            environment=Environment.TEST,
        ),
    )

    policy = PolicyConfig(
        policy_id="regression-policy",
        version="1.0",
        rules=[
            PolicyRule(
                rule_id="PASS-LOW",
                name="Pass low findings",
                description=(
                    "Low findings are permitted."
                ),
                severity="low",
                action=PolicyAction.PASS,
            ),
        ],
        fail_on_regression_failure=True,
    )

    policy_result = PolicyEngine().evaluate(
        [finding],
        [risk],
        policy,
        failed_regressions=[
            "BOLA-001"
        ],
    )

    assert policy_result.decision.value == "block"

    gate_input = ReleaseGateInput(
        application="SecureCommerce",
        version="1.0.0",
        commit_sha="regression-test-sha",
        policy_decision=ReleaseDecision(
            policy_result.decision.value
        ),
        blocking_findings=(
            policy_result.blocking_findings
        ),
        review_findings=(
            policy_result.review_findings
        ),
        failed_regressions=[
            "BOLA-001"
        ],
    )

    release_result = ReleaseGateEngine().evaluate(
        gate_input
    )

    assert release_result.decision == ReleaseDecision.BLOCK
    assert release_result.failed_regressions == [
        "BOLA-001"
    ]


def test_multiple_sources_are_preserved_through_correlation() -> None:
    """Verify source-specific evidence survives correlation."""
    findings = [
        build_finding(
            finding_id="SF-SAST-002",
            source="sast",
            title="SQL Injection",
            severity=Severity.HIGH,
            endpoint="/api/products",
            parameter="search",
            cwe="CWE-89",
        ),
        build_finding(
            finding_id="SF-DAST-002",
            source="dast",
            title="SQL Injection",
            severity=Severity.HIGH,
            endpoint="/api/products",
            parameter="search",
            cwe="CWE-89",
        ),
        build_finding(
            finding_id="SF-BURP-002",
            source="burp",
            title="SQL Injection",
            severity=Severity.HIGH,
            endpoint="/api/products",
            parameter="search",
            cwe="CWE-89",
        ),
    ]

    for finding in findings:
        finding.add_evidence(
            Evidence(
                evidence_id=(
                    f"E-{finding.finding_id}"
                ),
                source=finding.source,
                description=(
                    f"Evidence collected from "
                    f"{finding.source}."
                ),
            )
        )

    correlations = CorrelationEngine().correlate(
        findings
    )

    assert correlations

    all_source_ids = set()

    for correlation in correlations:
        all_source_ids.update(
            correlation.source_finding_ids
        )

    assert all_source_ids == {
        "SF-SAST-002",
        "SF-DAST-002",
        "SF-BURP-002",
    }
