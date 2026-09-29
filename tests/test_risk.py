"""Tests for SecureForge contextual risk evaluation."""

from secureforge.core.findings import (
Confidence,
Finding,
Severity,
)
from secureforge.core.risk import (
AssetImportance,
Environment,
RiskContext,
RiskEngine,
RiskLevel,
)

def build_finding(
*,
finding_id: str = "SF-0001",
severity: Severity = Severity.HIGH,
) -> Finding:
"""Create a representative finding for risk tests."""
return Finding(
finding_id=finding_id,
title="Broken Object Level Authorization",
source="dast",
application="SecureCommerce",
asset="securecommerce-api",
endpoint="/api/orders/1002",
parameter="id",
cwe="CWE-639",
owasp="API1",
security_requirement="SF-AUTHZ-001",
severity=severity,
confidence=Confidence.CONFIRMED,
description="A user can access another user's order.",
impact="Unauthorized access to protected order data.",
remediation="Enforce object-level authorization.",
)

def test_high_severity_finding_produces_high_base_risk() -> None:
"""Verify severity maps correctly to the base risk level."""
finding = build_finding(severity=Severity.HIGH)

assessment = RiskEngine().evaluate(finding)

assert assessment.base_severity == RiskLevel.HIGH
assert assessment.contextual_risk in {
    RiskLevel.HIGH,
    RiskLevel.CRITICAL,
}
assert assessment.risk_score >= 70

def test_critical_severity_finding_produces_critical_risk() -> None:
"""Verify critical findings start at critical risk."""
finding = build_finding(severity=Severity.CRITICAL)

assessment = RiskEngine().evaluate(finding)

assert assessment.base_severity == RiskLevel.CRITICAL
assert assessment.contextual_risk == RiskLevel.CRITICAL
assert assessment.risk_score >= 90

def test_internet_exposure_increases_risk() -> None:
"""Verify internet exposure increases contextual risk."""
finding = build_finding()

baseline = RiskEngine().evaluate(
    finding,
    RiskContext(
        internet_exposed=False,
    ),
)

exposed = RiskEngine().evaluate(
    finding,
    RiskContext(
        internet_exposed=True,
    ),
)

assert exposed.risk_score > baseline.risk_score
assert "internet-exposed asset" in exposed.factors

def test_missing_authentication_increases_risk() -> None:
"""Verify unauthenticated exploitation increases risk."""
finding = build_finding()

authenticated = RiskEngine().evaluate(
    finding,
    RiskContext(
        authentication_required=True,
    ),
)

unauthenticated = RiskEngine().evaluate(
    finding,
    RiskContext(
        authentication_required=False,
    ),
)

assert unauthenticated.risk_score > authenticated.risk_score
assert "no authentication required" in unauthenticated.factors

def test_sensitive_data_increases_risk() -> None:
"""Verify sensitive data involvement increases risk."""
finding = build_finding()

baseline = RiskEngine().evaluate(
    finding,
    RiskContext(
        sensitive_data=False,
    ),
)

sensitive = RiskEngine().evaluate(
    finding,
    RiskContext(
        sensitive_data=True,
    ),
)

assert sensitive.risk_score > baseline.risk_score
assert "sensitive data affected" in sensitive.factors

def test_exploit_evidence_increases_risk() -> None:
"""Verify demonstrated exploitation increases risk."""
finding = build_finding()

unconfirmed = RiskEngine().evaluate(
    finding,
    RiskContext(
        exploit_evidence=False,
    ),
)

confirmed = RiskEngine().evaluate(
    finding,
    RiskContext(
        exploit_evidence=True,
    ),
)

assert confirmed.risk_score > unconfirmed.risk_score
assert "exploit evidence available" in confirmed.factors

def test_critical_asset_increases_risk() -> None:
"""Verify critical asset importance increases risk."""
finding = build_finding()

medium_asset = RiskEngine().evaluate(
    finding,
    RiskContext(
        asset_importance=AssetImportance.MEDIUM,
    ),
)

critical_asset = RiskEngine().evaluate(
    finding,
    RiskContext(
        asset_importance=AssetImportance.CRITICAL,
    ),
)

assert critical_asset.risk_score > medium_asset.risk_score
assert "critical asset" in critical_asset.factors

def test_low_importance_asset_reduces_risk() -> None:
"""Verify low asset importance applies a downward adjustment."""
finding = build_finding()

medium_asset = RiskEngine().evaluate(
    finding,
    RiskContext(
        asset_importance=AssetImportance.MEDIUM,
    ),
)

low_asset = RiskEngine().evaluate(
    finding,
    RiskContext(
        asset_importance=AssetImportance.LOW,
    ),
)

assert low_asset.risk_score < medium_asset.risk_score
assert "low-importance asset" in low_asset.factors

def test_production_environment_increases_risk() -> None:
"""Verify production receives an environment adjustment."""
finding = build_finding()

staging = RiskEngine().evaluate(
    finding,
    RiskContext(
        environment=Environment.STAGING,
    ),
)

production = RiskEngine().evaluate(
    finding,
    RiskContext(
        environment=Environment.PRODUCTION,
    ),
)

assert production.risk_score > staging.risk_score

def test_lab_environment_reduces_risk() -> None:
"""Verify lab environments receive a downward adjustment."""
finding = build_finding()

test_environment = RiskEngine().evaluate(
    finding,
    RiskContext(
        environment=Environment.TEST,
    ),
)

lab = RiskEngine().evaluate(
    finding,
    RiskContext(
        environment=Environment.LAB,
    ),
)

assert lab.risk_score < test_environment.risk_score

def test_risk_score_is_bounded() -> None:
"""Verify contextual risk never leaves the 0-100 range."""
finding = build_finding(severity=Severity.CRITICAL)

assessment = RiskEngine().evaluate(
    finding,
    RiskContext(
        asset_importance=AssetImportance.CRITICAL,
        internet_exposed=True,
        authentication_required=False,
        sensitive_data=True,
        exploit_evidence=True,
        environment=Environment.PRODUCTION,
    ),
)

assert 0.0 <= assessment.risk_score <= 100.0

def test_risk_explanation_contains_decision_context() -> None:
"""Verify the risk result explains its contributing factors."""
finding = build_finding()

assessment = RiskEngine().evaluate(
    finding,
    RiskContext(
        internet_exposed=True,
        sensitive_data=True,
        exploit_evidence=True,
    ),
)

assert finding.finding_id in assessment.explanation
assert assessment.contextual_risk.value in assessment.explanation
assert "internet-exposed asset" in assessment.explanation
assert "sensitive data affected" in assessment.explanation
assert "exploit evidence available" in assessment.explanation

def test_finding_requirement_is_carried_into_default_context() -> None:
"""Verify the finding requirement is preserved in risk context."""
finding = build_finding()

assessment = RiskEngine().evaluate(finding)

assert assessment.context.security_requirement == "SF-AUTHZ-001"

def test_info_finding_remains_low_or_info_without_context() -> None:
"""Verify informational findings do not become high risk by default."""
finding = build_finding(severity=Severity.INFO)

assessment = RiskEngine().evaluate(
    finding,
    RiskContext(
        asset_importance=AssetImportance.MEDIUM,
        environment=Environment.TEST,
    ),
)

assert assessment.base_severity == RiskLevel.INFO
assert assessment.contextual_risk in {
    RiskLevel.INFO,
    RiskLevel.LOW,
}
assert assessment.risk_score < 40
