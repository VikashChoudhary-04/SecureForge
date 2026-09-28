```python
# SecureForge scan and validation integration tests

from __future__ import annotations

from secureforge.core.findings.models import (
    Confidence,
    Finding,
    Severity,
)
from secureforge.core.release_gate.engine import ReleaseGateEngine
from secureforge.core.risk.engine import RiskEngine
from secureforge.core.risk.models import RiskAssessment
from secureforge.core.policy.engine import PolicyEngine
from secureforge.core.policy.models import PolicyDecision
from secureforge.core.scan.security_pipeline import (
    SecurityPipeline,
)
from secureforge.validation import (
    ValidationEngine,
    build_validation_registry,
)


def build_pipeline() -> SecurityPipeline:
    validation_engine = ValidationEngine(
        registry=build_validation_registry()
    )

    return SecurityPipeline(
        risk_engine=RiskEngine(),
        policy_engine=PolicyEngine(),
        release_gate_engine=ReleaseGateEngine(),
        validation_engine=validation_engine,
    )


def make_finding(
    finding_id: str,
    *,
    endpoint: str = "/api/users/2",
    parameter: str | None = None,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        title=f"Test finding {finding_id}",
        source="integration-test",
        asset="SecureCommerce",
        application="SecureCommerce",
        endpoint=endpoint,
        parameter=parameter,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="Controlled integration-test finding.",
        impact="Controlled security impact.",
        remediation="Apply the documented security control.",
    )


class FakeValidationEngine:
    """Minimal validation-engine double for pipeline behavior tests."""

    def __init__(self, result):
        self.result = result

    def validate_many(self, requests):
        return [self.result for _ in requests]


def test_pipeline_accepts_validation_requests():
    pipeline = build_pipeline()

    finding = make_finding(
        "BOLA-001",
        endpoint="/api/users/2",
    )

    from secureforge.validation.models import (
        ValidationOutcome,
        ValidationRequest,
        ValidationResult,
    )

    request = ValidationRequest(
        finding_id="BOLA-001",
        target="http://localhost:5000",
        endpoint="/api/users/2",
    )

    result = ValidationResult(
        finding_id="BOLA-001",
        outcome=ValidationOutcome.REJECTED,
        message="Authorization was enforced.",
        validator="securecommerce",
        validated_at="2026-01-01T00:00:00+00:00",
    )

    pipeline.validation_engine = FakeValidationEngine(result)

    pipeline_result = pipeline.run(
        [finding],
        validation_requests=[request],
    )

    assert pipeline_result.validation is not None
    assert pipeline_result.validation.total == 1
    assert pipeline_result.validation.rejected == 1
    assert pipeline_result.validation_gate is not None
    assert pipeline_result.validation_results is not None
    assert len(pipeline_result.validation_results) == 1


def test_pipeline_blocks_when_validation_confirms_finding():
    pipeline = build_pipeline()

    finding = make_finding(
        "BOLA-001",
        endpoint="/api/users/2",
    )

    from secureforge.validation.models import (
        ValidationOutcome,
        ValidationRequest,
        ValidationResult,
    )

    request = ValidationRequest(
        finding_id="BOLA-001",
        target="http://localhost:5000",
        endpoint="/api/users/2",
    )

    result = ValidationResult(
        finding_id="BOLA-001",
        outcome=ValidationOutcome.CONFIRMED,
        message="Unauthorized object access was confirmed.",
        validator="securecommerce",
        validated_at="2026-01-01T00:00:00+00:00",
    )

    pipeline.validation_engine = FakeValidationEngine(result)

    pipeline_result = pipeline.run(
        [finding],
        validation_requests=[request],
    )

    assert pipeline_result.validation is not None
    assert pipeline_result.validation.confirmed == 1
    assert pipeline_result.validation_gate is not None
    assert pipeline_result.validation_gate.blocked is True
    assert pipeline_result.release_blocked is True


def test_pipeline_can_run_without_validation():
    pipeline = build_pipeline()

    finding = make_finding(
        "TEST-001",
        endpoint="/",
    )

    pipeline_result = pipeline.run(
        [finding],
        validation_requests=None,
    )

    assert pipeline_result.validation is None
    assert pipeline_result.validation_gate is None
    assert pipeline_result.validation_results is None


def test_pipeline_serialization_contains_validation_sections():
    pipeline = build_pipeline()

    finding = make_finding(
        "BOLA-001",
        endpoint="/api/users/2",
    )

    from secureforge.validation.models import (
        ValidationOutcome,
        ValidationRequest,
        ValidationResult,
    )

    request = ValidationRequest(
        finding_id="BOLA-001",
        target="http://localhost:5000",
        endpoint="/api/users/2",
    )

    result = ValidationResult(
        finding_id="BOLA-001",
        outcome=ValidationOutcome.CONFIRMED,
        message="Controlled BOLA validation confirmed the finding.",
        validator="securecommerce",
        validated_at="2026-01-01T00:00:00+00:00",
    )

    pipeline.validation_engine = FakeValidationEngine(result)

    pipeline_result = pipeline.run(
        [finding],
        validation_requests=[request],
    )

    data = pipeline_result.to_dict()

    assert "validation" in data
    assert "validation_results" in data
    assert "validation_gate" in data

    assert data["validation"]["confirmed"] == 1
    assert len(data["validation_results"]) == 1
    assert data["validation_results"][0]["finding_id"] == "BOLA-001"
    assert data["validation_gate"]["blocked"] is True
```
