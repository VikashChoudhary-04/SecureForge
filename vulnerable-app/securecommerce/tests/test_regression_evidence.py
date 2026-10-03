"""Tests for SecureCommerce security regression evidence."""

from __future__ import annotations

import json
from pathlib import Path

EVIDENCE_PATH = (
    Path(__file__).resolve().parents[1]
    / "evidence"
    / "sample-regression.json"
)


def load_regression_suite() -> dict:
    """Load the regression evidence fixture."""
    assert EVIDENCE_PATH.is_file()

    return json.loads(
        EVIDENCE_PATH.read_text(
            encoding="utf-8"
        )
    )


def test_regression_suite_has_expected_metadata():
    """Regression evidence should contain required metadata."""
    data = load_regression_suite()

    assert data["suite"] == (
        "securecommerce-security-regression"
    )
    assert data["version"] == "1.0.0"
    assert data["target"] == "SecureCommerce"


def test_regression_suite_contains_required_controls():
    """All major security regression controls should be present."""
    data = load_regression_suite()

    test_ids = {
        test["id"]
        for test in data["tests"]
    }

    expected_ids = {
        "BOLA-001",
        "SQLI-001",
        "XSS-001",
        "SECRET-001",
        "AUTHZ-001",
        "MISCONFIG-001",
    }

    assert expected_ids.issubset(test_ids)


def test_regression_tests_have_requirements():
    """Regression tests should map to SecureForge requirements."""
    data = load_regression_suite()

    for test in data["tests"]:
        assert test["requirement"].startswith("SF-")


def test_regression_tests_have_expected_results():
    """Each regression test should define expected secure behavior."""
    data = load_regression_suite()

    for test in data["tests"]:
        assert isinstance(test["expected"], dict)
        assert test["expected"]


def test_bola_regression_requires_forbidden_access():
    """BOLA regression should require denial of unauthorized access."""
    data = load_regression_suite()

    test = next(
        test
        for test in data["tests"]
        if test["id"] == "BOLA-001"
    )

    assert test["expected"]["unauthorized_object_access"] is False
    assert test["expected"]["response_status"] == 403


def test_secret_regression_requires_no_hardcoded_secret():
    """Secret regression should require absence of hardcoded secrets."""
    data = load_regression_suite()

    test = next(
        test
        for test in data["tests"]
        if test["id"] == "SECRET-001"
    )

    assert test["expected"]["hardcoded_secret"] is False

