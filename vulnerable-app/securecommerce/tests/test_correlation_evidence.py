"""Tests for SecureCommerce correlation evidence."""

from __future__ import annotations

import json
from pathlib import Path


EVIDENCE_PATH = (
    Path(__file__).resolve().parents[1]
    / "evidence"
    / "sample-correlation.json"
)


def load_correlation_evidence() -> dict:
    """Load the correlation evidence fixture."""
    assert EVIDENCE_PATH.is_file()

    return json.loads(
        EVIDENCE_PATH.read_text(
            encoding="utf-8"
        )
    )


def test_correlation_metadata():
    """Correlation evidence should contain canonical metadata."""
    data = load_correlation_evidence()

    correlation = data["correlation"]

    assert correlation["group_id"] == (
        "CORR-BOLA-001"
    )
    assert correlation["canonical_finding_id"] == (
        "SF-BOLA-001"
    )
    assert correlation["severity"] == "high"
    assert correlation["confidence"] == "confirmed"


def test_correlation_maps_to_authorization_requirement():
    """BOLA evidence should map to the authorization requirement."""
    data = load_correlation_evidence()

    correlation = data["correlation"]

    assert correlation["cwe"] == "CWE-639"
    assert correlation["owasp"] == (
        "API1:2023-Broken Object Level Authorization"
    )
    assert correlation["security_requirement"] == (
        "SF-AUTHZ-001"
    )


def test_correlation_contains_multiple_sources():
    """The same vulnerability should have multiple evidence sources."""
    data = load_correlation_evidence()

    sources = data["correlation"]["sources"]

    source_names = {
        source["source"]
        for source in sources
    }

    assert source_names == {
        "api",
        "dast",
        "manual",
    }


def test_correlation_contains_source_finding_ids():
    """Every correlated source should retain its original finding ID."""
    data = load_correlation_evidence()

    sources = data["correlation"]["sources"]

    finding_ids = {
        source["source_finding_id"]
        for source in sources
    }

    assert finding_ids == {
        "API-BOLA-001",
        "DAST-BOLA-001",
        "BURP-BOLA-001",
    }


def test_correlation_preserves_underlying_behavior():
    """Correlation should explain why observations belong together."""
    data = load_correlation_evidence()

    reason = data["correlation"]["reason"]

    assert reason["same_cwe"] is True
    assert reason["same_endpoint"] is True
    assert reason["same_parameter"] is True
    assert reason["same_requirement"] is True
    assert reason["same_underlying_behavior"] is True

