"""Tests for SecureForge finding identifier generation."""

from secureforge.core.findings.identifiers import FindingIdentifier


def build_data() -> dict[str, object]:
    """Create representative normalized finding data."""
    return {
        "source": "dast",
        "title": "SQL Injection",
        "asset": "securecommerce-api",
        "endpoint": "/api/products",
        "parameter": "search",
        "cwe": "CWE-89",
    }


def test_generate_returns_secureforge_identifier() -> None:
    """Verify generated IDs use the SecureForge prefix."""
    finding_id = FindingIdentifier.generate(
        source="dast",
        title="SQL Injection",
        asset="securecommerce-api",
        endpoint="/api/products",
        parameter="search",
        cwe="CWE-89",
    )

    assert finding_id.startswith("SF-")
    assert len(finding_id) == 15


def test_same_input_produces_same_identifier() -> None:
    """Verify identifier generation is deterministic."""
    first = FindingIdentifier.generate(
        source="dast",
        title="SQL Injection",
        asset="securecommerce-api",
        endpoint="/api/products",
        parameter="search",
        cwe="CWE-89",
    )

    second = FindingIdentifier.generate(
        source="dast",
        title="SQL Injection",
        asset="securecommerce-api",
        endpoint="/api/products",
        parameter="search",
        cwe="CWE-89",
    )

    assert first == second


def test_whitespace_differences_do_not_change_identifier() -> None:
    """Verify insignificant whitespace is normalized."""
    first = FindingIdentifier.generate(
        source="dast",
        title="SQL Injection",
        asset="securecommerce-api",
        endpoint="/api/products",
        parameter="search",
        cwe="CWE-89",
    )

    second = FindingIdentifier.generate(
        source="  DAST  ",
        title="  SQL   Injection ",
        asset=" securecommerce-api ",
        endpoint=" /api/products ",
        parameter=" search ",
        cwe=" CWE-89 ",
    )

    assert first == second


def test_case_differences_do_not_change_identifier() -> None:
    """Verify case normalization."""
    first = FindingIdentifier.generate(
        source="dast",
        title="SQL Injection",
        asset="securecommerce-api",
        endpoint="/api/products",
        parameter="search",
        cwe="CWE-89",
    )

    second = FindingIdentifier.generate(
        source="DAST",
        title="SQL INJECTION",
        asset="SECURECOMMERCE-API",
        endpoint="/API/PRODUCTS",
        parameter="SEARCH",
        cwe="cwe-89",
    )

    assert first == second


def test_different_source_changes_identifier() -> None:
    """Verify source is part of the finding identity."""
    first = FindingIdentifier.generate(
        source="sast",
        title="SQL Injection",
        asset="securecommerce-api",
    )

    second = FindingIdentifier.generate(
        source="dast",
        title="SQL Injection",
        asset="securecommerce-api",
    )

    assert first != second


def test_different_title_changes_identifier() -> None:
    """Verify finding title contributes to identity."""
    first = FindingIdentifier.generate(
        source="dast",
        title="SQL Injection",
        asset="securecommerce-api",
    )

    second = FindingIdentifier.generate(
        source="dast",
        title="Cross Site Scripting",
        asset="securecommerce-api",
    )

    assert first != second


def test_different_asset_changes_identifier() -> None:
    """Verify affected asset contributes to identity."""
    first = FindingIdentifier.generate(
        source="dast",
        title="SQL Injection",
        asset="securecommerce-api",
    )

    second = FindingIdentifier.generate(
        source="dast",
        title="SQL Injection",
        asset="securecommerce-admin",
    )

    assert first != second


def test_different_endpoint_changes_identifier() -> None:
    """Verify endpoint contributes to identity."""
    first = FindingIdentifier.generate(
        source="dast",
        title="SQL Injection",
        asset="securecommerce-api",
        endpoint="/api/products",
    )

    second = FindingIdentifier.generate(
        source="dast",
        title="SQL Injection",
        asset="securecommerce-api",
        endpoint="/api/orders",
    )

    assert first != second


def test_different_parameter_changes_identifier() -> None:
    """Verify parameter contributes to identity."""
    first = FindingIdentifier.generate(
        source="dast",
        title="SQL Injection",
        asset="securecommerce-api",
        parameter="search",
    )

    second = FindingIdentifier.generate(
        source="dast",
        title="SQL Injection",
        asset="securecommerce-api",
        parameter="id",
    )

    assert first != second


def test_different_cwe_changes_identifier() -> None:
    """Verify CWE contributes to identity."""
    first = FindingIdentifier.generate(
        source="dast",
        title="Security Finding",
        asset="securecommerce-api",
        cwe="CWE-89",
    )

    second = FindingIdentifier.generate(
        source="dast",
        title="Security Finding",
        asset="securecommerce-api",
        cwe="CWE-79",
    )

    assert first != second


def test_optional_fields_are_supported() -> None:
    """Verify optional endpoint, parameter, and CWE fields."""
    finding_id = FindingIdentifier.generate(
        source="sast",
        title="Hardcoded Secret",
        asset="securecommerce",
    )

    assert finding_id.startswith("SF-")
    assert len(finding_id) == 15


def test_from_finding_data_generates_identifier() -> None:
    """Verify dictionary-based ID generation."""
    finding_id = FindingIdentifier.from_finding_data(
        build_data()
    )

    expected = FindingIdentifier.generate(
        source="dast",
        title="SQL Injection",
        asset="securecommerce-api",
        endpoint="/api/products",
        parameter="search",
        cwe="CWE-89",
    )

    assert finding_id == expected


def test_from_finding_data_handles_missing_optional_fields() -> None:
    """Verify dictionary input can omit optional attributes."""
    finding_id = FindingIdentifier.from_finding_data(
        {
            "source": "sast",
            "title": "Hardcoded Secret",
            "asset": "securecommerce",
        }
    )

    expected = FindingIdentifier.generate(
        source="sast",
        title="Hardcoded Secret",
        asset="securecommerce",
    )

    assert finding_id == expected


def test_missing_dictionary_values_do_not_raise() -> None:
    """Verify incomplete normalized data still receives an identifier."""
    finding_id = FindingIdentifier.from_finding_data({})

    assert finding_id.startswith("SF-")
    assert len(finding_id) == 15


def test_identifier_is_uppercase_after_prefix() -> None:
    """Verify the digest portion uses uppercase hexadecimal."""
    finding_id = FindingIdentifier.generate(
        source="dast",
        title="SQL Injection",
        asset="securecommerce-api",
    )

    digest = finding_id.removeprefix("SF-")

    assert digest == digest.upper()
    assert all(
        character in "0123456789ABCDEF"
        for character in digest
    )
