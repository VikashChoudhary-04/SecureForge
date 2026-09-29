"""Tests for SecureForge evidence normalization."""

import pytest

from secureforge.core.normalization import (
NormalizationAdapter,
NormalizationResult,
RawEvidence,
)

class TestAdapter(NormalizationAdapter):
"""Test adapter used to exercise the normalization contract."""


source_name = "test-scanner"

def parse(
    self,
    raw_evidence: RawEvidence,
) -> NormalizationResult:
    """Convert test evidence into a normalized finding."""
    self.validate_input(raw_evidence)

    finding = self.build_finding_data(
        finding_id="SF-TEST-001",
        title="Test SQL Injection",
        application="SecureCommerce",
        asset="securecommerce-api",
        severity="high",
        description="A test SQL injection finding.",
        impact="Database queries may be manipulated.",
        remediation="Use parameterized queries.",
        endpoint="/api/products",
        parameter="search",
        cwe="CWE-89",
    )

    return NormalizationResult(
        source=self.source_name,
        findings=[finding],
        evidence=[raw_evidence],
    )


def build_raw_evidence() -> RawEvidence:
"""Create representative scanner evidence."""
return RawEvidence(
source="test-scanner",
source_version="1.0.0",
source_reference="TEST-001",
target="http://localhost:8000",
raw_data={
"id": "TEST-001",
"title": "SQL Injection",
"severity": "high",
},
)

def test_raw_evidence_is_created_correctly() -> None:
"""Verify raw evidence stores scanner information."""
evidence = build_raw_evidence()


assert evidence.source == "test-scanner"
assert evidence.source_version == "1.0.0"
assert evidence.source_reference == "TEST-001"
assert evidence.target == "http://localhost:8000"
assert evidence.raw_data["severity"] == "high"


def test_normalization_result_starts_empty() -> None:
"""Verify an empty normalization result has expected defaults."""
result = NormalizationResult(source="test-scanner")


assert result.findings == []
assert result.evidence == []
assert result.warnings == []
assert result.errors == []
assert result.success is True
assert result.finding_count == 0
assert result.has_errors is False


def test_adapter_normalizes_raw_evidence() -> None:
"""Verify an adapter produces normalized finding data."""
adapter = TestAdapter()
evidence = build_raw_evidence()


result = adapter.parse(evidence)

assert result.success is True
assert result.source == "test-scanner"
assert result.finding_count == 1
assert result.has_errors is False

finding = result.findings[0]

assert finding["finding_id"] == "SF-TEST-001"
assert finding["source"] == "test-scanner"
assert finding["severity"] == "high"
assert finding["cwe"] == "CWE-89"
assert finding["endpoint"] == "/api/products"


def test_adapter_preserves_raw_evidence() -> None:
"""Verify normalized results retain their source evidence."""
adapter = TestAdapter()
evidence = build_raw_evidence()


result = adapter.parse(evidence)

assert len(result.evidence) == 1
assert result.evidence[0].source_reference == "TEST-001"


def test_normalization_result_counts_findings() -> None:
"""Verify finding_count reflects normalized findings."""
result = NormalizationResult(
source="test-scanner",
findings=[
{"finding_id": "SF-001"},
{"finding_id": "SF-002"},
],
)


assert result.finding_count == 2


def test_normalization_result_detects_errors() -> None:
"""Verify has_errors becomes true when errors exist."""
result = NormalizationResult(
source="test-scanner",
errors=["Unable to parse scanner output."],
success=False,
)


assert result.has_errors is True
assert result.success is False


def test_adapter_rejects_wrong_source() -> None:
"""Verify adapters reject evidence from another source."""
adapter = TestAdapter()


evidence = RawEvidence(
    source="different-scanner",
    raw_data={},
)

with pytest.raises(ValueError, match="Expected source"):
    adapter.parse(evidence)


def test_adapter_rejects_empty_source() -> None:
"""Verify empty evidence sources are rejected."""
adapter = TestAdapter()


evidence = RawEvidence(
    source="test-scanner",
    raw_data={},
)

evidence.source = ""

with pytest.raises(ValueError, match="Evidence source cannot be empty"):
    adapter.parse(evidence)

