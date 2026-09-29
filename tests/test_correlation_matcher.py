"""Tests for the SecureForge finding correlation matcher."""

from secureforge.core.correlation import (
CorrelationType,
)
from secureforge.core.correlation.matcher import FindingMatcher
from secureforge.core.findings import Finding

def build_finding(
finding_id: str,
*,
title: str = "SQL Injection",
asset: str = "securecommerce-api",
endpoint: str = "/api/products",
parameter: str | None = "search",
cwe: str | None = "CWE-89",
) -> Finding:
"""Create a representative finding."""
return Finding(
finding_id=finding_id,
title=title,
source="dast",
application="SecureCommerce",
asset=asset,
endpoint=endpoint,
parameter=parameter,
cwe=cwe,
severity="high",
description="Security finding.",
impact="Security impact.",
remediation="Apply remediation.",
)

def test_match_returns_same_cwe_signal() -> None:
"""Verify matching CWEs produce a correlation signal."""
first = build_finding("SF-001")
second = build_finding(
"SF-002",
endpoint="/api/profile",
parameter="name",
)


signals = FindingMatcher().match(
    first,
    second,
)

assert "same_cwe" in signals


def test_match_returns_same_asset_signal() -> None:
"""Verify matching assets produce a correlation signal."""
first = build_finding("SF-001")
second = build_finding(
"SF-002",
endpoint="/api/profile",
parameter="name",
cwe="CWE-79",
)


signals = FindingMatcher().match(
    first,
    second,
)

assert "same_asset" in signals


def test_match_returns_same_endpoint_signal() -> None:
"""Verify matching endpoints produce a correlation signal."""
first = build_finding("SF-001")
second = build_finding(
"SF-002",
parameter="id",
cwe="CWE-639",
)


signals = FindingMatcher().match(
    first,
    second,
)

assert "same_endpoint" in signals


def test_match_normalizes_endpoint_case_and_trailing_slash() -> None:
"""Verify endpoint normalization is used during matching."""
first = build_finding(
"SF-001",
endpoint="/API/Products/",
)


second = build_finding(
    "SF-002",
    endpoint="/api/products?search=test",
    parameter="query",
)

assert FindingMatcher().same_endpoint(
    first,
    second,
)


def test_match_returns_same_parameter_signal() -> None:
"""Verify matching parameters produce a signal."""
first = build_finding("SF-001")
second = build_finding(
"SF-002",
endpoint="/api/profile",
parameter="SEARCH",
cwe="CWE-79",
)


signals = FindingMatcher().match(
    first,
    second,
)

assert "same_parameter" in signals


def test_match_returns_similar_title_signal() -> None:
"""Verify meaningful title overlap produces a signal."""
first = build_finding(
"SF-001",
title="SQL Injection vulnerability",
)


second = build_finding(
    "SF-002",
    title="Confirmed SQL Injection",
    cwe="CWE-89",
)

signals = FindingMatcher().match(
    first,
    second,
)

assert "similar_title" in signals


def test_match_returns_multiple_signals() -> None:
"""Verify multiple independent signals can be returned."""
first = build_finding("SF-001")


second = build_finding(
    "SF-002",
)

signals = FindingMatcher().match(
    first,
    second,
)

assert set(signals) == {
    "same_cwe",
    "same_asset",
    "same_endpoint",
    "same_parameter",
    "similar_title",
}


def test_match_does_not_match_same_finding() -> None:
"""Verify a finding is never correlated with itself."""
finding = build_finding("SF-001")


signals = FindingMatcher().match(
    finding,
    finding,
)

assert signals == []


def test_same_cwe_is_case_insensitive() -> None:
"""Verify CWE matching ignores case."""
first = build_finding(
"SF-001",
cwe="cwe-89",
)


second = build_finding(
    "SF-002",
    cwe="CWE-89",
)

assert FindingMatcher().same_cwe(
    first,
    second,
)


def test_same_cwe_returns_false_when_missing() -> None:
"""Verify missing CWE values do not match."""
first = build_finding(
"SF-001",
cwe=None,
)


second = build_finding(
    "SF-002",
    cwe="CWE-89",
)

assert not FindingMatcher().same_cwe(
    first,
    second,
)


def test_same_parameter_returns_false_when_missing() -> None:
"""Verify missing parameters do not match."""
first = build_finding(
"SF-001",
parameter=None,
)


second = build_finding(
    "SF-002",
    parameter="search",
)

assert not FindingMatcher().same_parameter(
    first,
    second,
)


def test_same_endpoint_returns_false_when_missing() -> None:
"""Verify missing endpoints do not match."""
first = build_finding(
"SF-001",
endpoint=None,
)


second = build_finding(
    "SF-002",
    endpoint="/api/products",
)

assert not FindingMatcher().same_endpoint(
    first,
    second,
)


def test_similar_title_requires_meaningful_overlap() -> None:
"""Verify weak title overlap does not create a signal."""
first = build_finding(
"SF-001",
title="SQL Injection",
)


second = build_finding(
    "SF-002",
    title="Cross Site Scripting",
    cwe="CWE-79",
    asset="different-api",
    endpoint="/different",
    parameter="name",
)

assert not FindingMatcher().similar_title(
    first,
    second,
)


def test_normalize_endpoint_removes_query_string() -> None:
"""Verify endpoint query strings are excluded from comparison."""
normalized = FindingMatcher.normalize_endpoint(
"/api/orders/123?include=items"
)


assert normalized == "/api/orders/123"


def test_normalize_endpoint_removes_trailing_slash() -> None:
"""Verify trailing slashes are normalized."""
normalized = FindingMatcher.normalize_endpoint(
"/api/orders/123/"
)


assert normalized == "/api/orders/123"


def test_normalize_endpoint_lowercases_value() -> None:
"""Verify endpoint normalization is case-insensitive."""
normalized = FindingMatcher.normalize_endpoint(
"/API/ORDERS"
)


assert normalized == "/api/orders"


def test_correlation_types_map_signals() -> None:
"""Verify signals map to their documented correlation types."""
matcher = FindingMatcher()


types = matcher.correlation_types(
    [
        "same_cwe",
        "same_asset",
        "same_endpoint",
        "same_parameter",
        "similar_title",
    ]
)

assert types == [
    CorrelationType.SAME_VULNERABILITY,
    CorrelationType.SAME_ASSET,
    CorrelationType.SAME_ENDPOINT,
    CorrelationType.SAME_PARAMETER,
    CorrelationType.RELATED,
]


def test_primary_correlation_type_prefers_same_vulnerability() -> None:
"""Verify CWE correlation has the highest primary priority."""
matcher = FindingMatcher()


primary = matcher.primary_correlation_type(
    [
        "same_asset",
        "same_endpoint",
        "same_cwe",
    ]
)

assert primary == CorrelationType.SAME_VULNERABILITY


def test_primary_correlation_type_prefers_endpoint_over_asset() -> None:
"""Verify endpoint matching outranks asset-only matching."""
matcher = FindingMatcher()


primary = matcher.primary_correlation_type(
    [
        "same_asset",
        "same_endpoint",
    ]
)

assert primary == CorrelationType.SAME_ENDPOINT


def test_primary_correlation_type_defaults_to_related() -> None:
"""Verify unknown or empty signals default to related."""
matcher = FindingMatcher()


primary = matcher.primary_correlation_type(
    []
)

assert primary == CorrelationType.RELATED

