```python id="m6q9xr"
"""Tests for SecureForge security-pipeline orchestration."""

from secureforge.core.scan.security_pipeline import (
    SecurityPipeline,
)


def test_security_pipeline_evaluates_findings(
    sample_finding,
) -> None:
    """Run the complete core security pipeline."""
    pipeline = SecurityPipeline()

    result = pipeline.evaluate(
        [sample_finding]
    )

    assert result.findings
    assert result.risk is not None
    assert result.policy is not None
    assert result.release_gate is not None

    assert (
        result.findings[0].finding_id
        == sample_finding.finding_id
    )


def test_security_pipeline_handles_empty_findings() -> None:
    """Evaluate a scan with no findings."""
    pipeline = SecurityPipeline()

    result = pipeline.evaluate([])

    assert result.findings == []
    assert result.risk is not None
    assert result.policy is not None
    assert result.release_gate is not None


def test_security_pipeline_passes_tool_errors_to_policy(
    sample_finding,
) -> None:
    """Forward integration errors into policy evaluation."""
    pipeline = SecurityPipeline()

    result = pipeline.evaluate(
        [sample_finding],
        tool_errors=[
            "SCA scanner unavailable."
        ],
    )

    assert result.policy is not None
    assert result.release_gate is not None


def test_security_pipeline_summarizes_result(
    sample_finding,
) -> None:
    """Produce a compact serializable pipeline summary."""
    pipeline = SecurityPipeline()

    result = pipeline.evaluate(
        [sample_finding]
    )

    summary = pipeline.summarize(
        result
    )

    assert summary["finding_count"] == 1
    assert "risk_score" in summary
    assert "highest_severity" in summary
    assert "policy" in summary
    assert "release_status" in summary
    assert "release_allowed" in summary


def test_security_pipeline_result_to_dict(
    sample_finding,
) -> None:
    """Serialize the complete pipeline result."""
    pipeline = SecurityPipeline()

    result = pipeline.evaluate(
        [sample_finding]
    )

    payload = result.to_dict()

    assert set(
        payload
    ).issuperset(
        {
            "findings",
            "risk",
            "policy",
            "release_gate",
        }
    )

    assert isinstance(
        payload["findings"],
        list,
    )

    assert isinstance(
        payload["risk"],
        dict,
    )

    assert isinstance(
        payload["policy"],
        dict,
    )

    assert isinstance(
        payload["release_gate"],
        dict,
    )
```
