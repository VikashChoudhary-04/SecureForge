"""Tests for the SecureForge normalization finding factory."""

import pytest

from secureforge.core.findings import (
Finding,
Severity,
)
from secureforge.core.normalization import NormalizationResult
from secureforge.core.normalization.factory import (
NormalizationFindingFactory,
)

def build_finding_data(
title: str = "SQL Injection",
) -> dict:
"""Create representative normalized finding data."""
return {
"title": title,
"source": "dast",
"application": "SecureCommerce",
"asset": "securecommerce-api",
"endpoint": "/api/products",
"parameter": "search",
"cwe": "CWE-89",
"owasp": "A03",
"security_requirement": "SF-INPUT-001",
"severity": "high",
"description": "SQL injection was confirmed.",
"impact": "Database queries may be manipulated.",
"remediation": "Use parameterized queries.",
}

def build_result(
findings: list[dict] | None = None,
) -> NormalizationResult:
"""Create a successful normalization result."""
return NormalizationResult(
source="dast",
findings=(
findings
if findings is not None
else [build_finding_data()]
),
)

def test_factory_creates_findings_from_result() -> None:
"""Verify normalized findings become Finding objects."""
result = build_result()


findings = NormalizationFindingFactory().create(
    result
)

assert len(findings) == 1
assert isinstance(findings[0], Finding)
assert findings[0].title == "SQL Injection"
assert findings[0].severity == Severity.HIGH


def test_factory_creates_multiple_findings() -> None:
"""Verify multiple normalized findings are converted."""
result = build_result(
[
build_finding_data("SQL Injection"),
build_finding_data("Cross Site Scripting"),
build_finding_data("Broken Access Control"),
]
)


findings = NormalizationFindingFactory().create(
    result
)

assert len(findings) == 3
assert [
    finding.title
    for finding in findings
] == [
    "SQL Injection",
    "Cross Site Scripting",
    "Broken Access Control",
]


def test_factory_rejects_unsuccessful_result() -> None:
"""Verify failed normalization cannot produce findings."""
result = NormalizationResult(
source="dast",
success=False,
errors=[
"Parser failed."
],
)


with pytest.raises(
    ValueError,
    match="unsuccessful normalization result",
):
    NormalizationFindingFactory().create(
        result
    )


def test_factory_accepts_empty_successful_result() -> None:
"""Verify a successful result with no findings is valid."""
result = NormalizationResult(
source="dast",
findings=[],
)


findings = NormalizationFindingFactory().create(
    result
)

assert findings == []


def test_factory_create_many_combines_results() -> None:
"""Verify findings from multiple results are combined."""
first = build_result(
[
build_finding_data("SQL Injection"),
]
)


second = NormalizationResult(
    source="sast",
    findings=[
        {
            **build_finding_data(
                "Potential SQL Injection"
            ),
            "source": "sast",
            "severity": "medium",
        }
    ],
)

findings = NormalizationFindingFactory().create_many(
    [
        first,
        second,
    ]
)

assert len(findings) == 2
assert findings[0].source == "dast"
assert findings[1].source == "sast"


def test_factory_create_many_preserves_order() -> None:
"""Verify finding order follows normalization result order."""
first = build_result(
[
build_finding_data("First Finding"),
]
)


second = build_result(
    [
        build_finding_data("Second Finding"),
    ]
)

findings = NormalizationFindingFactory().create_many(
    [
        first,
        second,
    ]
)

assert [
    finding.title
    for finding in findings
] == [
    "First Finding",
    "Second Finding",
]


def test_factory_create_from_data() -> None:
"""Verify direct conversion from normalized dictionaries."""
data = [
build_finding_data("SQL Injection"),
build_finding_data("Cross Site Scripting"),
]


findings = NormalizationFindingFactory().create_from_data(
    data
)

assert len(findings) == 2
assert all(
    isinstance(
        finding,
        Finding,
    )
    for finding in findings
)


def test_factory_rejects_invalid_finding_data() -> None:
"""Verify invalid normalized data is rejected."""
invalid_data = build_finding_data()


del invalid_data["title"]

result = build_result(
    [invalid_data]
)

with pytest.raises(
    ValueError,
    match="Missing required finding fields",
):
    NormalizationFindingFactory().create(
        result
    )


def test_factory_uses_injected_finding_factory() -> None:
"""Verify a custom FindingFactory can be injected."""
from secureforge.core.findings import FindingFactory


factory = FindingFactory()

normalization_factory = NormalizationFindingFactory(
    finding_factory=factory
)

result = build_result()

findings = normalization_factory.create(
    result
)

assert len(findings) == 1
assert findings[0].finding_id.startswith("SF-")


def test_factory_generates_deterministic_ids() -> None:
"""Verify equivalent normalization results produce stable IDs."""
first_result = build_result()
second_result = build_result()


factory = NormalizationFindingFactory()

first = factory.create(
    first_result
)[0]

second = factory.create(
    second_result
)[0]

assert first.finding_id == second.finding_id

