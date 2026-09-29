"""Tests for the SecureForge finding store."""

import pytest

from secureforge.core.findings import (
Confidence,
Finding,
FindingStatus,
Severity,
)
from secureforge.core.findings.store import FindingStore

def build_finding(
*,
finding_id: str,
source: str = "dast",
status: FindingStatus = FindingStatus.OPEN,
asset: str = "securecommerce-api",
requirement: str = "SF-AUTHZ-001",
) -> Finding:
"""Create a representative finding."""
return Finding(
finding_id=finding_id,
title="Broken Object Level Authorization",
source=source,
application="SecureCommerce",
asset=asset,
endpoint="/api/orders/1002",
parameter="id",
cwe="CWE-639",
owasp="API1",
security_requirement=requirement,
severity=Severity.HIGH,
confidence=Confidence.CONFIRMED,
description="A user can access another user's order.",
impact="Unauthorized order access.",
remediation="Enforce object-level authorization.",
status=status,
)

def test_store_starts_empty() -> None:
"""Verify a new store contains no findings."""
store = FindingStore()


assert len(store) == 0
assert store.all() == []


def test_add_stores_finding() -> None:
"""Verify a finding can be inserted."""
store = FindingStore()
finding = build_finding(finding_id="SF-0001")


result = store.add(finding)

assert result is finding
assert len(store) == 1
assert store.get("SF-0001") is finding


def test_duplicate_finding_id_is_rejected() -> None:
"""Verify duplicate IDs cannot be silently inserted."""
store = FindingStore()
finding = build_finding(finding_id="SF-0001")


store.add(finding)

with pytest.raises(
    ValueError,
    match="already exists",
):
    store.add(
        build_finding(
            finding_id="SF-0001",
            source="burp",
        )
    )


def test_upsert_replaces_existing_finding() -> None:
"""Verify upsert replaces an existing finding with the same ID."""
store = FindingStore()


original = build_finding(
    finding_id="SF-0001",
    source="sast",
)
replacement = build_finding(
    finding_id="SF-0001",
    source="dast",
)

store.add(original)
result = store.upsert(replacement)

assert result is replacement
assert store.get("SF-0001") is replacement
assert len(store) == 1
assert store.get("SF-0001").source == "dast"


def test_get_returns_none_for_unknown_finding() -> None:
"""Verify unknown IDs return None."""
store = FindingStore()


assert store.get("SF-9999") is None


def test_require_returns_existing_finding() -> None:
"""Verify require returns a stored finding."""
store = FindingStore()
finding = build_finding(finding_id="SF-0001")


store.add(finding)

assert store.require("SF-0001") is finding


def test_require_raises_for_unknown_finding() -> None:
"""Verify require raises a useful lookup error."""
store = FindingStore()


with pytest.raises(
    KeyError,
    match="was not found",
):
    store.require("SF-9999")


def test_remove_returns_deleted_finding() -> None:
"""Verify findings can be removed."""
store = FindingStore()
finding = build_finding(finding_id="SF-0001")


store.add(finding)

removed = store.remove("SF-0001")

assert removed is finding
assert len(store) == 0
assert store.get("SF-0001") is None


def test_remove_unknown_finding_raises() -> None:
"""Verify removing an unknown finding raises an error."""
store = FindingStore()


with pytest.raises(
    KeyError,
    match="was not found",
):
    store.remove("SF-9999")


def test_contains_checks_finding_id() -> None:
"""Verify finding existence checks."""
store = FindingStore()
finding = build_finding(finding_id="SF-0001")


assert store.contains("SF-0001") is False

store.add(finding)

assert store.contains("SF-0001") is True


def test_by_status_filters_findings() -> None:
"""Verify status-based lookup."""
store = FindingStore()


store.add(
    build_finding(
        finding_id="SF-0001",
        status=FindingStatus.OPEN,
    )
)
store.add(
    build_finding(
        finding_id="SF-0002",
        status=FindingStatus.VERIFIED,
    )
)
store.add(
    build_finding(
        finding_id="SF-0003",
        status=FindingStatus.OPEN,
    )
)

results = store.by_status(FindingStatus.OPEN)

assert [
    finding.finding_id
    for finding in results
] == [
    "SF-0001",
    "SF-0003",
]


def test_by_source_is_case_insensitive() -> None:
"""Verify source filtering is normalized."""
store = FindingStore()


store.add(
    build_finding(
        finding_id="SF-0001",
        source="DAST",
    )
)
store.add(
    build_finding(
        finding_id="SF-0002",
        source="sast",
    )
)

results = store.by_source("dast")

assert [
    finding.finding_id
    for finding in results
] == ["SF-0001"]


def test_by_asset_is_case_insensitive() -> None:
"""Verify asset filtering is normalized."""
store = FindingStore()


store.add(
    build_finding(
        finding_id="SF-0001",
        asset="SecureCommerce-API",
    )
)
store.add(
    build_finding(
        finding_id="SF-0002",
        asset="another-api",
    )
)

results = store.by_asset("securecommerce-api")

assert [
    finding.finding_id
    for finding in results
] == ["SF-0001"]


def test_by_requirement_filters_findings() -> None:
"""Verify security requirement filtering."""
store = FindingStore()


store.add(
    build_finding(
        finding_id="SF-0001",
        requirement="SF-AUTHZ-001",
    )
)
store.add(
    build_finding(
        finding_id="SF-0002",
        requirement="SF-INPUT-001",
    )
)

results = store.by_requirement("SF-AUTHZ-001")

assert [
    finding.finding_id
    for finding in results
] == ["SF-0001"]


def test_open_findings_excludes_resolved_statuses() -> None:
"""Verify resolved findings are excluded from open findings."""
store = FindingStore()


store.add(
    build_finding(
        finding_id="SF-OPEN",
        status=FindingStatus.OPEN,
    )
)
store.add(
    build_finding(
        finding_id="SF-IN-PROGRESS",
        status=FindingStatus.IN_PROGRESS,
    )
)
store.add(
    build_finding(
        finding_id="SF-REMEDIATED",
        status=FindingStatus.REMEDIATED,
    )
)
store.add(
    build_finding(
        finding_id="SF-VERIFIED",
        status=FindingStatus.VERIFIED,
    )
)
store.add(
    build_finding(
        finding_id="SF-ACCEPTED",
        status=FindingStatus.ACCEPTED,
    )
)

results = store.open_findings()

assert {
    finding.finding_id
    for finding in results
} == {
    "SF-OPEN",
    "SF-IN-PROGRESS",
}


def test_update_status_changes_stored_finding() -> None:
"""Verify status updates operate on stored objects."""
store = FindingStore()


store.add(
    build_finding(
        finding_id="SF-0001",
        status=FindingStatus.OPEN,
    )
)

updated = store.update_status(
    "SF-0001",
    FindingStatus.IN_PROGRESS,
)

assert updated.status == FindingStatus.IN_PROGRESS
assert store.require("SF-0001").status == FindingStatus.IN_PROGRESS


def test_add_many_inserts_multiple_findings() -> None:
"""Verify batch insertion."""
store = FindingStore()


count = store.add_many(
    [
        build_finding(finding_id="SF-0001"),
        build_finding(finding_id="SF-0002"),
        build_finding(finding_id="SF-0003"),
    ]
)

assert count == 3
assert len(store) == 3


def test_iteration_returns_findings() -> None:
"""Verify the store can be iterated."""
store = FindingStore()


store.add(build_finding(finding_id="SF-0001"))
store.add(build_finding(finding_id="SF-0002"))

assert [
    finding.finding_id
    for finding in store
] == [
    "SF-0001",
    "SF-0002",
]


def test_clear_removes_all_findings() -> None:
"""Verify the store can be reset."""
store = FindingStore()


store.add(build_finding(finding_id="SF-0001"))
store.add(build_finding(finding_id="SF-0002"))

store.clear()

assert len(store) == 0
assert store.all() == []

