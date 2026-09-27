"""Tests for the SecureForge normalization pipeline."""

from secureforge.core.normalization import (
NormalizationAdapter,
NormalizationPipeline,
NormalizationRegistry,
NormalizationResult,
RawEvidence,
)

class TestAdapter(NormalizationAdapter):
"""Successful test normalization adapter."""

```
source_name = "test-scanner"

def parse(
    self,
    raw_evidence: RawEvidence,
) -> NormalizationResult:
    """Normalize test scanner evidence."""
    self.validate_input(raw_evidence)

    return NormalizationResult(
        source=self.source_name,
        findings=[
            self.build_finding_data(
                finding_id="SF-TEST-001",
                title="Test Security Finding",
                application="SecureCommerce",
                asset="securecommerce-api",
                severity="high",
                description="A test security finding.",
                impact="Controlled test impact.",
                remediation="Apply the test remediation.",
            )
        ],
        evidence=[raw_evidence],
    )
```

class FailingAdapter(NormalizationAdapter):
"""Adapter that intentionally raises an error."""

```
source_name = "failing-scanner"

def parse(
    self,
    raw_evidence: RawEvidence,
) -> NormalizationResult:
    """Raise a controlled adapter failure."""
    raise RuntimeError(
        "Simulated parser failure."
    )
```

def build_evidence(
source: str = "test-scanner",
) -> RawEvidence:
"""Create representative raw evidence."""
return RawEvidence(
source=source,
source_version="1.0.0",
source_reference="TEST-001",
target="http://localhost:8000",
raw_data={
"title": "Test Security Finding",
"severity": "high",
},
)

def build_pipeline() -> NormalizationPipeline:
"""Create a pipeline containing the test adapters."""
registry = NormalizationRegistry()

```
registry.register(TestAdapter())
registry.register(FailingAdapter())

return NormalizationPipeline(registry)
```

def test_pipeline_normalizes_supported_evidence() -> None:
"""Verify supported evidence is normalized successfully."""
pipeline = build_pipeline()

```
result = pipeline.normalize(
    build_evidence()
)

assert result.success is True
assert result.source == "test-scanner"
assert result.finding_count == 1
assert result.has_errors is False
assert result.findings[0]["finding_id"] == "SF-TEST-001"
```

def test_pipeline_preserves_raw_evidence() -> None:
"""Verify normalized results retain raw evidence."""
pipeline = build_pipeline()
evidence = build_evidence()

```
result = pipeline.normalize(evidence)

assert len(result.evidence) == 1
assert result.evidence[0] is evidence
```

def test_pipeline_handles_unknown_source() -> None:
"""Verify missing adapters produce a failed result."""
pipeline = build_pipeline()

```
result = pipeline.normalize(
    build_evidence(
        source="unknown-scanner"
    )
)

assert result.success is False
assert result.finding_count == 0
assert result.has_errors is True
assert len(result.errors) == 1
assert "No normalization adapter is registered" in result.errors[0]
```

def test_pipeline_handles_adapter_failure() -> None:
"""Verify adapter exceptions become normalization errors."""
pipeline = build_pipeline()

```
result = pipeline.normalize(
    build_evidence(
        source="failing-scanner"
    )
)

assert result.success is False
assert result.has_errors is True
assert "Simulated parser failure" in result.errors[0]
assert len(result.evidence) == 1
```

def test_pipeline_normalizes_multiple_evidence_items() -> None:
"""Verify batch normalization."""
pipeline = build_pipeline()

```
evidence_items = [
    build_evidence(),
    build_evidence(),
]

results = pipeline.normalize_many(
    evidence_items
)

assert len(results) == 2
assert all(
    result.success
    for result in results
)
assert all(
    result.finding_count == 1
    for result in results
)
```

def test_pipeline_normalize_many_preserves_order() -> None:
"""Verify batch results preserve input order."""
pipeline = build_pipeline()

```
first = build_evidence()
second = RawEvidence(
    source="failing-scanner",
    source_reference="FAIL-001",
    raw_data={},
)

results = pipeline.normalize_many(
    [
        first,
        second,
    ]
)

assert results[0].source == "test-scanner"
assert results[0].success is True

assert results[1].source == "failing-scanner"
assert results[1].success is False
```

def test_pipeline_aggregates_successful_results() -> None:
"""Verify multiple successful results can be aggregated."""
pipeline = build_pipeline()

```
results = pipeline.normalize_many(
    [
        build_evidence(),
        build_evidence(),
    ]
)

aggregate = pipeline.aggregate(results)

assert aggregate.success is True
assert aggregate.finding_count == 2
assert len(aggregate.evidence) == 2
assert aggregate.errors == []
```

def test_pipeline_aggregate_preserves_errors() -> None:
"""Verify aggregation retains adapter errors."""
pipeline = build_pipeline()

```
results = pipeline.normalize_many(
    [
        build_evidence(),
        build_evidence(
            source="failing-scanner"
        ),
    ]
)

aggregate = pipeline.aggregate(results)

assert aggregate.success is False
assert aggregate.finding_count == 1
assert len(aggregate.evidence) == 2
assert len(aggregate.errors) == 1
assert "Simulated parser failure" in aggregate.errors[0]
```

def test_pipeline_aggregate_preserves_warnings() -> None:
"""Verify warnings survive result aggregation."""
pipeline = build_pipeline()

```
first = NormalizationResult(
    source="test-scanner",
    warnings=[
        "Optional field was missing."
    ],
)

second = NormalizationResult(
    source="test-scanner",
    warnings=[
        "Target metadata was incomplete."
    ],
)

aggregate = pipeline.aggregate(
    [
        first,
        second,
    ]
)

assert aggregate.success is True
assert aggregate.warnings == [
    "Optional field was missing.",
    "Target metadata was incomplete.",
]
```

def test_pipeline_aggregate_combines_sources() -> None:
"""Verify aggregate results identify contributing sources."""
pipeline = build_pipeline()

```
first = NormalizationResult(
    source="sast",
    findings=[
        {"finding_id": "SAST-001"}
    ],
)

second = NormalizationResult(
    source="dast",
    findings=[
        {"finding_id": "DAST-001"}
    ],
)

aggregate = pipeline.aggregate(
    [
        first,
        second,
    ]
)

assert aggregate.source == "sast,dast"
assert aggregate.finding_count == 2
```

def test_pipeline_aggregate_removes_duplicate_source_names() -> None:
"""Verify repeated sources appear only once in aggregate metadata."""
pipeline = build_pipeline()

```
first = NormalizationResult(
    source="sast",
)

second = NormalizationResult(
    source="sast",
)

third = NormalizationResult(
    source="dast",
)

aggregate = pipeline.aggregate(
    [
        first,
        second,
        third,
    ]
)

assert aggregate.source == "sast,dast"
```

def test_empty_aggregation_is_successful() -> None:
"""Verify aggregating no results produces an empty successful result."""
pipeline = build_pipeline()

```
aggregate = pipeline.aggregate([])

assert aggregate.success is True
assert aggregate.source == ""
assert aggregate.findings == []
assert aggregate.evidence == []
assert aggregate.errors == []
assert aggregate.warnings == []
```
