```python id="z4n8q1"
"""Tests for the SecureForge security verification pipeline."""

from secureforge.core.scan.security_pipeline import (
    SecurityPipeline,
)


def test_pipeline_evaluates_findings(
    sample_findings,
) -> None:
    """Evaluate findings through correlation, risk, policy, and release gate."""
    pipeline = SecurityPipeline()

    result = pipeline.evaluate(
        sample_findings
    )

    assert result.findings
    assert result.risk is not None
    assert result.policy is not None
    assert result.release_gate is not None

    assert result.risk.finding_count == len(
        result.findings
    )

    assert result.release_allowed == (
        result.release_gate.release_allowed
    )

    assert result.release_blocked == (
        not result.release_gate.release_allowed
    )


def test_pipeline_returns_serializable_result(
    sample_findings,
) -> None:
    """Serialize the complete pipeline result."""
    pipeline = SecurityPipeline()

    result = pipeline.evaluate(
        sample_findings
    )

    payload = result.to_dict()

    assert isinstance(
        payload,
        dict,
    )

    assert "findings" in payload
    assert "risk" in payload
    assert "policy" in payload
    assert "release_gate" in payload

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


def test_pipeline_preserves_tool_errors(
    sample_findings,
) -> None:
    """Tool execution errors remain visible to policy evaluation."""
    pipeline = SecurityPipeline()

    result = pipeline.evaluate(
        sample_findings,
        tool_errors=[
            "DAST scanner failed to execute."
        ],
    )

    assert result.policy is not None

    assert any(
        "DAST scanner failed to execute."
        in violation
        for violation in result.policy.violations
    )


def test_pipeline_handles_empty_findings() -> None:
    """An empty finding set still produces a complete evaluation."""
    pipeline = SecurityPipeline()

    result = pipeline.evaluate(
        []
    )

    assert result.findings == []
    assert result.risk.finding_count == 0
    assert result.policy is not None
    assert result.release_gate is not None


def test_pipeline_exposes_release_decision(
    sample_findings,
) -> None:
    """Expose the final release decision directly."""
    pipeline = SecurityPipeline()

    result = pipeline.evaluate(
        sample_findings
    )

    assert isinstance(
        result.release_allowed,
        bool,
    )

    assert isinstance(
        result.release_blocked,
        bool,
    )

    assert (
        result.release_allowed
        != result.release_blocked
        or (
            result.release_allowed is False
            and result.release_blocked is True
        )
    )


def test_pipeline_summarize_contains_core_sections(
    sample_findings,
) -> None:
    """Produce a compact pipeline summary."""
    pipeline = SecurityPipeline()

    result = pipeline.evaluate(
        sample_findings
    )

    summary = pipeline.summarize(
        result
    )

    assert isinstance(
        summary,
        dict,
    )

    assert "finding_count" in summary
    assert "risk" in summary
    assert "policy" in summary
    assert "release_gate" in summary

    assert summary["finding_count"] == len(
        result.findings
    )


def test_pipeline_accepts_custom_components(
    sample_findings,
) -> None:
    """Allow callers to inject pipeline components."""
    from secureforge.core.correlation.engine import (
        CorrelationEngine,
    )
    from secureforge.core.policy.engine import (
        PolicyEngine,
    )
    from secureforge.core.release_gate.engine import (
        ReleaseGateEngine,
    )
    from secureforge.core.risk.engine import (
        RiskEngine,
    )

    pipeline = SecurityPipeline(
        correlation_engine=CorrelationEngine(),
        risk_engine=RiskEngine(),
        policy_engine=PolicyEngine(),
        release_gate_engine=ReleaseGateEngine(),
    )

    result = pipeline.evaluate(
        sample_findings
    )

    assert result.findings
    assert result.risk is not None
    assert result.policy is not None
    assert result.release_gate is not None
```
