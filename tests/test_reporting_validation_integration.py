# SecureForge reporting and validation integration tests

from __future__ import annotations

from pathlib import Path

from secureforge.core.findings.models import (
    Confidence,
    Finding,
    Severity,
)
from secureforge.core.release_gate.engine import ReleaseGateEngine
from secureforge.core.risk.engine import RiskEngine
from secureforge.core.policy.engine import PolicyEngine
from secureforge.core.scan.security_pipeline import (
    SecurityPipeline,
)
from secureforge.reporting.service import ReportingService
from secureforge.validation import (
    ValidationEngine,
    build_validation_registry,
)
from secureforge.validation.models import (
    ValidationOutcome,
    ValidationRequest,
    ValidationResult,
)


class FakeValidationEngine:
    """Controlled validation-engine double."""

    def __init__(
        self,
        result: ValidationResult,
    ) -> None:
        self.result = result

    def validate_many(
        self,
        requests: list[ValidationRequest],
    ) -> list[ValidationResult]:
        return [
            self.result
            for _ in requests
        ]


def make_finding() -> Finding:
    return Finding(
        finding_id="BOLA-001",
        title="Broken object-level authorization",
        source="integration-test",
        asset="SecureCommerce",
        application="SecureCommerce",
        endpoint="/api/users/2",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description=(
            "Controlled BOLA finding for reporting integration."
        ),
        impact=(
            "An unauthorized user may access another user's object."
        ),
        remediation=(
            "Enforce object-level authorization before returning "
            "the requested resource."
        ),
    )


def make_pipeline(
    validation_result: ValidationResult,
) -> SecurityPipeline:
    validation_engine = ValidationEngine(
        registry=build_validation_registry()
    )

    pipeline = SecurityPipeline(
        risk_engine=RiskEngine(),
        policy_engine=PolicyEngine(),
        release_gate_engine=ReleaseGateEngine(),
        validation_engine=validation_engine,
    )

    pipeline.validation_engine = FakeValidationEngine(
        validation_result
    )

    return pipeline


def make_validation_request() -> ValidationRequest:
    return ValidationRequest(
        finding_id="BOLA-001",
        target="http://localhost:5000",
        endpoint="/api/users/2",
    )


def test_validation_data_is_present_in_security_report():
    validation_result = ValidationResult(
        finding_id="BOLA-001",
        outcome=ValidationOutcome.CONFIRMED,
        message=(
            "Controlled BOLA validation confirmed "
            "unauthorized object access."
        ),
        validator="securecommerce",
        validated_at="2026-01-01T00:00:00+00:00",
    )

    pipeline = make_pipeline(
        validation_result
    )

    pipeline_result = pipeline.run(
        [make_finding()],
        validation_requests=[
            make_validation_request()
        ],
    )

    report = ReportingService().build(
        pipeline_result
    )

    assert report.validation is not None
    assert report.validation.total == 1
    assert report.validation.confirmed == 1

    assert len(
        report.validation_results
    ) == 1

    assert (
        report.validation_results[0].finding_id
        == "BOLA-001"
    )

    assert (
        report.validation_results[0].outcome
        == "confirmed"
    )

    assert report.validation_gate is not None
    assert report.validation_gate.blocked is True


def test_json_report_contains_validation_sections(
    tmp_path: Path,
):
    validation_result = ValidationResult(
        finding_id="BOLA-001",
        outcome=ValidationOutcome.CONFIRMED,
        message="BOLA confirmed.",
        validator="securecommerce",
        validated_at="2026-01-01T00:00:00+00:00",
    )

    pipeline = make_pipeline(
        validation_result
    )

    pipeline_result = pipeline.run(
        [make_finding()],
        validation_requests=[
            make_validation_request()
        ],
    )

    service = ReportingService()

    report = service.build(
        pipeline_result
    )

    output = tmp_path / "security-report.json"

    service.write_json(
        report,
        output,
    )

    assert output.exists()

    content = output.read_text(
        encoding="utf-8"
    )

    assert '"validation"' in content
    assert '"validation_results"' in content
    assert '"validation_gate"' in content
    assert '"BOLA-001"' in content
    assert '"confirmed"' in content


def test_html_report_contains_validation_information(
    tmp_path: Path,
):
    validation_result = ValidationResult(
        finding_id="BOLA-001",
        outcome=ValidationOutcome.CONFIRMED,
        message=(
            "Controlled validation confirmed "
            "the vulnerability."
        ),
        validator="securecommerce",
        validated_at="2026-01-01T00:00:00+00:00",
    )

    pipeline = make_pipeline(
        validation_result
    )

    pipeline_result = pipeline.run(
        [make_finding()],
        validation_requests=[
            make_validation_request()
        ],
    )

    service = ReportingService()

    report = service.build(
        pipeline_result
    )

    output = tmp_path / "security-report.html"

    service.write_html(
        report,
        output,
    )

    assert output.exists()

    content = output.read_text(
        encoding="utf-8"
    )

    assert "Validation" in content
    assert "BOLA-001" in content
    assert "confirmed" in content
    assert "Controlled validation confirmed" in content


def test_validation_error_is_preserved_in_report():
    validation_result = ValidationResult(
        finding_id="BOLA-001",
        outcome=ValidationOutcome.ERROR,
        message="Target was unreachable.",
        validator="securecommerce",
        validated_at="2026-01-01T00:00:00+00:00",
    )

    pipeline = make_pipeline(
        validation_result
    )

    pipeline_result = pipeline.run(
        [make_finding()],
        validation_requests=[
            make_validation_request()
        ],
    )

    report = ReportingService().build(
        pipeline_result
    )

    assert report.validation is not None
    assert report.validation.errors == 1

    assert (
        report.validation_results[0].outcome
        == "error"
    )

    assert report.validation_gate is not None
