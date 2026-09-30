"""Tests for the SecureForge risk engine."""

from secureforge.core.findings import Finding, Severity
from secureforge.core.risk import (
    AssetImportance,
    Environment,
    RiskContext,
    RiskEngine,
    RiskLevel,
)
from secureforge.core.risk.scoring import RiskScorer


class FixedScorer(RiskScorer):
    """Test scorer returning a deterministic score."""

    def __init__(
        self,
        score: float,
        factors: list[str] | None = None,
    ) -> None:
        self.score = score
        self.factors = factors or []

    def calculate(
        self,
        finding: Finding,
        context: RiskContext,
    ) -> tuple[float, list[str]]:
        """Return the configured test score."""
        return self.score, list(self.factors)


def build_finding(
    severity: Severity = Severity.HIGH,
) -> Finding:
    """Create a representative finding."""
    return Finding(
        finding_id="SF-001",
        title="SQL Injection",
        source="dast",
        application="SecureCommerce",
        asset="securecommerce-api",
        endpoint="/api/products",
        parameter="search",
        cwe="CWE-89",
        security_requirement="SF-INPUT-001",
        severity=severity,
        description="SQL injection was confirmed.",
        impact="Database queries may be manipulated.",
        remediation="Use parameterized queries.",
    )


def build_context(
    **overrides: object,
) -> RiskContext:
    """Create a representative risk context."""
    data: dict[str, object] = {
        "asset_importance": AssetImportance.MEDIUM,
        "internet_exposed": False,
        "authentication_required": True,
        "sensitive_data": False,
        "exploit_evidence": False,
        "environment": Environment.UNKNOWN,
        "security_requirement": "SF-INPUT-001",
    }

    data.update(overrides)

    return RiskContext.model_validate(data)


def test_engine_evaluates_finding() -> None:
    """Verify the engine produces a risk assessment."""
    assessment = RiskEngine().evaluate(
        build_finding(),
        build_context(),
    )

    assert assessment.finding_id == "SF-001"
    assert assessment.base_severity == RiskLevel.HIGH
    assert assessment.contextual_risk == RiskLevel.HIGH
    assert assessment.risk_score == 70.0


def test_engine_uses_finding_requirement_by_default() -> None:
    """Verify the finding requirement is copied into default context."""
    assessment = RiskEngine().evaluate(
        build_finding(),
    )

    assert assessment.context.security_requirement == (
        "SF-INPUT-001"
    )


def test_engine_accepts_explicit_context() -> None:
    """Verify caller-provided context is preserved."""
    context = build_context(
        asset_importance=AssetImportance.CRITICAL,
        internet_exposed=True,
        environment=Environment.PRODUCTION,
    )

    assessment = RiskEngine().evaluate(
        build_finding(),
        context,
    )

    assert assessment.context == context
    assert assessment.risk_score == 91.0
    assert assessment.contextual_risk == RiskLevel.CRITICAL


def test_engine_produces_explanation() -> None:
    """Verify the assessment contains an explainable result."""
    assessment = RiskEngine().evaluate(
        build_finding(),
        build_context(
            internet_exposed=True,
            sensitive_data=True,
        ),
    )

    assert "SF-001" in assessment.explanation
    assert "contextual risk" in assessment.explanation
    assert "internet-exposed asset" in assessment.explanation
    assert "sensitive data affected" in assessment.explanation


def test_engine_reports_no_factors_when_context_is_neutral() -> None:
    """Verify neutral context produces a concise explanation."""
    assessment = RiskEngine().evaluate(
        build_finding(),
        build_context(),
    )

    assert assessment.factors == []
    assert (
        "No additional contextual risk factors were applied."
        in assessment.explanation
    )


def test_engine_uses_injected_scorer() -> None:
    """Verify a custom scorer can be injected."""
    scorer = FixedScorer(
        82.5,
        [
            "custom-test-factor"
        ],
    )

    engine = RiskEngine(
        scorer=scorer
    )

    assessment = engine.evaluate(
        build_finding(),
        build_context(),
    )

    assert assessment.risk_score == 82.5
    assert assessment.contextual_risk == RiskLevel.HIGH
    assert assessment.factors == [
        "custom-test-factor"
    ]


def test_engine_maps_critical_score() -> None:
    """Verify scores at or above 90 are critical."""
    engine = RiskEngine(
        scorer=FixedScorer(90.0)
    )

    assessment = engine.evaluate(
        build_finding(),
        build_context(),
    )

    assert assessment.contextual_risk == RiskLevel.CRITICAL


def test_engine_maps_high_score() -> None:
    """Verify scores from 70 through 89.99 are high."""
    engine = RiskEngine(
        scorer=FixedScorer(70.0)
    )

    assessment = engine.evaluate(
        build_finding(),
        build_context(),
    )

    assert assessment.contextual_risk == RiskLevel.HIGH


def test_engine_maps_medium_score() -> None:
    """Verify scores from 40 through 69.99 are medium."""
    engine = RiskEngine(
        scorer=FixedScorer(40.0)
    )

    assessment = engine.evaluate(
        build_finding(),
        build_context(),
    )

    assert assessment.contextual_risk == RiskLevel.MEDIUM


def test_engine_maps_low_score() -> None:
    """Verify scores from 15 through 39.99 are low."""
    engine = RiskEngine(
        scorer=FixedScorer(15.0)
    )

    assessment = engine.evaluate(
        build_finding(),
        build_context(),
    )

    assert assessment.contextual_risk == RiskLevel.LOW


def test_engine_maps_info_score() -> None:
    """Verify scores below 15 are informational."""
    engine = RiskEngine(
        scorer=FixedScorer(14.9)
    )

    assessment = engine.evaluate(
        build_finding(),
        build_context(),
    )

    assert assessment.contextual_risk == RiskLevel.INFO


def test_engine_preserves_base_severity() -> None:
    """Verify contextual scoring does not change base severity."""
    engine = RiskEngine(
        scorer=FixedScorer(95.0)
    )

    assessment = engine.evaluate(
        build_finding(Severity.LOW),
        build_context(),
    )

    assert assessment.base_severity == RiskLevel.LOW
    assert assessment.contextual_risk == RiskLevel.CRITICAL


def test_engine_handles_info_finding() -> None:
    """Verify informational findings are supported."""
    assessment = RiskEngine().evaluate(
        build_finding(Severity.INFO),
        build_context(),
    )

    assert assessment.base_severity == RiskLevel.INFO
    assert assessment.risk_score == 5.0
    assert assessment.contextual_risk == RiskLevel.INFO


def test_engine_evaluated_at_is_populated() -> None:
    """Verify every assessment receives an evaluation timestamp."""
    assessment = RiskEngine().evaluate(
        build_finding(),
        build_context(),
    )

    assert assessment.evaluated_at
    assert "T" in assessment.evaluated_at
