"""Infrastructure configuration tests for SecureCommerce."""

from __future__ import annotations

from pathlib import Path


INFRA_DIR = (
    Path(__file__).resolve().parents[1] / "infra"
)


def read_infrastructure_file(
    filename: str,
) -> str:
    """Read one Terraform configuration file."""
    path = INFRA_DIR / filename

    assert path.is_file(), (
        f"Expected infrastructure file does not exist: {path}"
    )

    return path.read_text(
        encoding="utf-8"
    )


def test_vulnerable_configuration_contains_public_exposure():
    """The vulnerable configuration should expose the lab application."""
    content = read_infrastructure_file(
        "main.tf"
    )

    assert '"0.0.0.0"' in content
    assert '"5000"' in content


def test_vulnerable_configuration_contains_insecure_storage():
    """The vulnerable configuration should contain insecure storage."""
    content = read_infrastructure_file(
        "main.tf"
    )

    assert 'encryption = "disabled"' in content
    assert 'access     = "public"' in content


def test_vulnerable_configuration_contains_excessive_permissions():
    """The vulnerable configuration should contain wildcard permissions."""
    content = read_infrastructure_file(
        "main.tf"
    )

    assert 'permissions = "*"' in content
    assert 'role        = "administrator"' in content


def test_variable_defaults_are_intentionally_insecure():
    """Terraform variables should reproduce the vulnerable lab state."""
    content = read_infrastructure_file(
        "variables.tf"
    )

    assert 'default     = "0.0.0.0"' in content
    assert "default     = false" in content
    assert "default     = true" in content
    assert 'default     = "*"' in content


def test_tfvars_reproduce_vulnerable_lab_state():
    """The laboratory tfvars should enable the vulnerable configuration."""
    content = read_infrastructure_file(
        "terraform.tfvars"
    )

    assert 'application_host   = "0.0.0.0"' in content
    assert "storage_encryption = false" in content
    assert "storage_public_access = true" in content
    assert 'permission_scope   = "*"' in content


def test_secure_configuration_restricts_application_exposure():
    """The remediated configuration should restrict application exposure."""
    content = read_infrastructure_file(
        "secure.tf"
    )

    assert 'host        = "127.0.0.1"' in content
    assert 'port        = "5000"' in content


def test_secure_configuration_enables_private_storage():
    """The remediated configuration should use protected storage."""
    content = read_infrastructure_file(
        "secure.tf"
    )

    assert 'encryption = "enabled"' in content
    assert 'access     = "private"' in content


def test_secure_configuration_uses_least_privilege():
    """The remediated configuration should avoid wildcard permissions."""
    content = read_infrastructure_file(
        "secure.tf"
    )

    assert (
        'permissions = '
        '"read-write-required-resources-only"'
    ) in content

    assert 'role        = "securecommerce-application"' in content


def test_outputs_expose_security_relevant_state():
    """Terraform outputs should expose relevant lab security state."""
    content = read_infrastructure_file(
        "outputs.tf"
    )

    assert "public_application" in content
    assert "storage_encryption" in content
    assert "storage_public_access" in content
    assert "permission_scope" in content

