from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_security_requirements_file_exists() -> None:
    """Verify that the repository security requirements file exists."""
    requirements_file = REPOSITORY_ROOT / "SECURITY.md"
    assert requirements_file.is_file()


def test_security_requirements_file_is_not_empty() -> None:
    """Verify that the security requirements file contains content."""
    requirements_file = REPOSITORY_ROOT / "SECURITY.md"
    assert requirements_file.read_text(encoding="utf-8").strip()


def test_security_requirements_file_contains_expected_sections() -> None:
    """Verify that SECURITY.md documents the expected security-reporting guidance."""
    requirements_file = REPOSITORY_ROOT / "SECURITY.md"
    content = requirements_file.read_text(encoding="utf-8")

    assert "Security" in content
    assert "Vulnerability" in content
    assert "Report" in content
