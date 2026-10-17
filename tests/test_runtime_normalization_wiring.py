"""Tests for production normalization wiring."""

from __future__ import annotations

from secureforge.config.runtime import build_runtime
from secureforge.core.normalization import NormalizationPipeline
from secureforge.core.scan.normalizer import ScanResultNormalizer


def test_build_runtime_injects_scan_result_normalizer() -> None:
    """Production runtime should inject normalization into ScanRunner."""
    runtime = build_runtime()

    assert isinstance(
        runtime.runner.normalizer,
        ScanResultNormalizer,
    )


def test_build_runtime_normalizer_uses_normalization_pipeline() -> None:
    """Production normalizer should use the canonical normalization pipeline."""
    runtime = build_runtime()

    normalizer = runtime.runner.normalizer

    assert isinstance(
        normalizer,
        ScanResultNormalizer,
    )
    assert isinstance(
        normalizer.pipeline,
        NormalizationPipeline,
    )


def test_build_runtime_normalization_pipeline_has_generic_integrations() -> None:
    """Production normalization should register all compatible integrations."""
    runtime = build_runtime()

    normalizer = runtime.runner.normalizer

    assert isinstance(
        normalizer,
        ScanResultNormalizer,
    )

    assert normalizer.pipeline.registry.sources() == [
        "api",
        "container",
        "dast",
        "iac",
        "nmap",
        "sast",
        "sca",
        "secrets",
    ]


def test_production_runtime_normalizes_real_tool_output(tmp_path) -> None:
    """Production runtime should execute and normalize scanner output."""
    from secureforge.core.config import (
        ScanConfiguration,
        ScanProfile,
        TargetConfiguration,
        TargetType,
        ToolConfiguration,
    )

    runtime = build_runtime()

    configuration = ScanConfiguration(
        application="SecureCommerce",
        version="1.0.0",
        profile=ScanProfile.QUICK,
        environment="lab",
        target=TargetConfiguration(
            name="securecommerce-local",
            target_type=TargetType.WEB_AND_API,
            base_url="http://localhost:5000",
        ),
        tools=[
            ToolConfiguration(
                name="sast",
                command=[
                    "python",
                    "-c",
                    (
                        "import json; "
                        "print(json.dumps({'findings': [{"
                        "'title': 'SQL Injection', "
                        "'severity': 'high', "
                        "'description': 'Test SQL injection finding', "
                        "'asset': 'securecommerce-api', "
                        "'cwe': 'CWE-89', "
                        "'remediation': 'Use parameterized queries'"
                        "}]}))"
                    ),
                ],
            )
        ],
    )

    scan = runtime.runner.run(configuration)

    assert scan.status.value == "completed"
    assert len(scan.tool_results) == 1
    assert scan.tool_results[0].succeeded is True

    assert len(scan.findings) == 1
    finding = scan.findings[0]

    assert finding.title == "SQL Injection"
    assert finding.source == "sast"
    assert finding.severity.value == "high"
