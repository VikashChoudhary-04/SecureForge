"""Tests for the SecureForge scan-result normalizer."""

from datetime import datetime, timezone

from secureforge.core.normalization import (
    NormalizationAdapter,
    NormalizationPipeline,
    NormalizationRegistry,
)
from secureforge.core.scan.models import (
    ToolExecutionResult,
    ToolExecutionStatus,
)
from secureforge.core.scan.normalizer import (
    ScanResultNormalizer,
)


class FakeAdapter(NormalizationAdapter):
    """Controlled normalization adapter for tests."""

    source_name = "sast"

    def parse(self, raw_evidence):
        """Convert controlled tool output into a finding."""
        return type(
            "Result",
            (),
            {
                "source": self.source_name,
                "findings": [
                    {
                        "title": "SQL Injection",
                        "source": "sast",
                        "application": "SecureCommerce",
                        "asset": "securecommerce-api",
                        "endpoint": "/api/products",
                        "parameter": "search",
                        "cwe": "CWE-89",
                        "severity": "high",
                        "description": "Controlled SQL injection finding.",
                        "impact": "Database queries may be manipulated.",
                        "remediation": "Use parameterized queries.",
                    }
                ],
                "evidence": [],
                "warnings": [],
                "errors": [],
                "success": True,
            },
        )()


class FailingAdapter(NormalizationAdapter):
    """Controlled adapter that fails during parsing."""

    source_name = "dast"

    def parse(self, raw_evidence):
        """Raise a controlled parsing error."""
        raise ValueError("Invalid scanner output.")


def build_pipeline() -> NormalizationPipeline:
    """Create a normalization pipeline with test adapters."""
    registry = NormalizationRegistry()

    registry.register(
        FakeAdapter()
    )

    registry.register(
        FailingAdapter()
    )

    return NormalizationPipeline(
        registry
    )


def build_result(
    *,
    integration: str = "sast",
    status: ToolExecutionStatus = ToolExecutionStatus.SUCCESS,
) -> ToolExecutionResult:
    """Create a representative tool execution result."""
    timestamp = datetime.now(timezone.utc)

    return ToolExecutionResult(
        tool_name=integration,
        integration=integration,
        status=status,
        command=[
            "scanner",
            "test",
        ],
        exit_code=0,
        stdout="scanner output",
        stderr="",
        duration_seconds=1.5,
        started_at=timestamp,
        completed_at=timestamp,
        metadata={
            "source_version": "1.0.0",
            "scanner_run": "RUN-001",
        },
    )


def test_build_evidence_preserves_tool_information() -> None:
    """Verify tool execution data becomes raw evidence."""
    normalizer = ScanResultNormalizer(
        build_pipeline()
    )

    result = build_result()

    evidence = normalizer.build_evidence(
        result,
        target="http://localhost:5000",
        application="SecureCommerce",
    )

    assert evidence.source == "sast"
    assert evidence.source_version == "1.0.0"
    assert evidence.target == "http://localhost:5000"
    assert evidence.raw_data["tool_name"] == "sast"
    assert evidence.raw_data["integration"] == "sast"
    assert evidence.raw_data["stdout"] == "scanner output"
    assert evidence.raw_data["exit_code"] == 0


def test_build_evidence_preserves_metadata() -> None:
    """Verify tool metadata is preserved."""
    normalizer = ScanResultNormalizer(
        build_pipeline()
    )

    evidence = normalizer.build_evidence(
        build_result(),
        application="SecureCommerce",
    )

    assert evidence.metadata["source_version"] == "1.0.0"
    assert evidence.metadata["scanner_run"] == "RUN-001"
    assert evidence.metadata["application"] == "SecureCommerce"


def test_build_evidence_does_not_overwrite_application_metadata() -> None:
    """Verify existing application metadata takes precedence."""
    result = build_result()

    result.metadata["application"] = "ExistingApplication"

    normalizer = ScanResultNormalizer(
        build_pipeline()
    )

    evidence = normalizer.build_evidence(
        result,
        application="SecureCommerce",
    )

    assert (
        evidence.metadata["application"]
        == "ExistingApplication"
    )


def test_build_evidence_uses_completed_timestamp() -> None:
    """Verify completed time is preferred as evidence collection time."""
    result = build_result()

    normalizer = ScanResultNormalizer(
        build_pipeline()
    )

    evidence = normalizer.build_evidence(
        result
    )

    assert evidence.collected_at == result.completed_at


def test_build_evidence_falls_back_to_started_timestamp() -> None:
    """Verify started time is used when completion time is unavailable."""
    result = build_result()
    result.completed_at = None

    normalizer = ScanResultNormalizer(
        build_pipeline()
    )

    evidence = normalizer.build_evidence(
        result
    )

    assert evidence.collected_at == result.started_at


def test_normalize_result_uses_pipeline() -> None:
    """Verify one result is passed through normalization."""
    normalizer = ScanResultNormalizer(
        build_pipeline()
    )

    normalization_result = normalizer.normalize_result(
        build_result(),
        target="http://localhost:5000",
        application="SecureCommerce",
    )

    assert normalization_result.success is True
    assert normalization_result.source == "sast"
    assert normalization_result.finding_count == 1


def test_findings_from_result_creates_canonical_finding() -> None:
    """Verify normalized scanner data becomes a Finding."""
    normalizer = ScanResultNormalizer(
        build_pipeline()
    )

    normalization_result, findings = (
        normalizer.findings_from_result(
            build_result(),
            target="http://localhost:5000",
            application="SecureCommerce",
        )
    )

    assert normalization_result.success is True
    assert len(findings) == 1

    finding = findings[0]

    assert finding.title == "SQL Injection"
    assert finding.source == "sast"
    assert finding.application == "SecureCommerce"
    assert finding.asset == "securecommerce-api"
    assert finding.endpoint == "/api/products"
    assert finding.parameter == "search"
    assert finding.cwe == "CWE-89"
    assert finding.severity.value == "high"


def test_findings_from_result_generates_finding_id() -> None:
    """Verify canonical finding IDs are generated."""
    normalizer = ScanResultNormalizer(
        build_pipeline()
    )

    _, findings = normalizer.findings_from_result(
        build_result()
    )

    assert findings[0].finding_id.startswith(
        "SF-"
    )


def test_findings_from_failed_normalization_return_no_findings() -> None:
    """Verify failed normalization does not create findings."""
    normalizer = ScanResultNormalizer(
        build_pipeline()
    )

    result = build_result(
        integration="dast"
    )

    normalization_result, findings = (
        normalizer.findings_from_result(
            result
        )
    )

    assert normalization_result.success is False
    assert findings == []
    assert normalization_result.errors


def test_normalize_unknown_source_returns_failure() -> None:
    """Verify unknown integrations are handled safely."""
    normalizer = ScanResultNormalizer(
        build_pipeline()
    )

    result = build_result(
        integration="unknown"
    )

    normalization_result = normalizer.normalize_result(
        result
    )

    assert normalization_result.success is False
    assert normalization_result.errors


def test_normalize_results_processes_multiple_results() -> None:
    """Verify multiple tool results are normalized."""
    normalizer = ScanResultNormalizer(
        build_pipeline()
    )

    results = [
        build_result(
            integration="sast"
        ),
        build_result(
            integration="sast"
        ),
    ]

    normalized = normalizer.normalize_results(
        results
    )

    assert len(normalized) == 2
    assert all(
        result.success
        for result in normalized
    )


def test_findings_from_results_creates_findings_from_successful_results() -> None:
    """Verify batch normalization produces canonical findings."""
    normalizer = ScanResultNormalizer(
        build_pipeline()
    )

    results = [
        build_result(
            integration="sast"
        ),
        build_result(
            integration="dast"
        ),
    ]

    normalization_results, findings = (
        normalizer.findings_from_results(
            results,
            application="SecureCommerce",
        )
    )

    assert len(normalization_results) == 2
    assert len(findings) == 1
    assert normalization_results[0].success is True
    assert normalization_results[1].success is False


def test_findings_from_results_preserves_finding_order() -> None:
    """Verify successful findings retain normalization order."""
    normalizer = ScanResultNormalizer(
        build_pipeline()
    )

    results = [
        build_result(
            integration="sast"
        ),
        build_result(
            integration="sast"
        ),
    ]

    _, findings = normalizer.findings_from_results(
        results
    )

    assert len(findings) == 2

    assert [
        finding.title
        for finding in findings
    ] == [
        "SQL Injection",
        "SQL Injection",
    ]


def test_failed_tool_execution_data_is_preserved() -> None:
    """Verify failed tool output remains available as evidence."""
    normalizer = ScanResultNormalizer(
        build_pipeline()
    )

    result = build_result(
        status=ToolExecutionStatus.FAILED
    )

    result.exit_code = 2
    result.stderr = "scanner failed"
    result.error = "Scanner execution failed."

    evidence = normalizer.build_evidence(
        result
    )

    assert evidence.raw_data["status"] == "failed"
    assert evidence.raw_data["exit_code"] == 2
    assert evidence.raw_data["stderr"] == "scanner failed"
    assert (
        evidence.raw_data["error"]
        == "Scanner execution failed."
    )


def test_normalizer_can_use_custom_finding_factory() -> None:
    """Verify a custom finding factory can be injected."""

    class CustomFactory:
        def create(self, result):
            return ["custom-finding"]

        def create_many(self, results):
            return ["custom-finding"]

    normalizer = ScanResultNormalizer(
        build_pipeline(),
        finding_factory=CustomFactory(),
    )

    normalization_result, findings = (
        normalizer.findings_from_result(
            build_result()
        )
    )

    assert normalization_result.success is True
    assert findings == ["custom-finding"]
