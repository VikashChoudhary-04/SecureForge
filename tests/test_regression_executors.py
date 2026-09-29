"""Tests for SecureCommerce regression executors."""

from _future_ import annotations

from pathlib import Path

from secureforge.regression import (
RegressionTest,
SecureCommerceRegressionExecutor,
)

def build_test(
test_id: str,
*,
target: str = "/test",
requirement: str = "SF-API-001",
) -> RegressionTest:
"""Build a representative regression test."""
return RegressionTest(
test_id=test_id,
name=f"Regression {test_id}",
security_requirement=requirement,
description="Security regression test.",
objective="Prevent security regression.",
target=target,
method="GET",
expected_result="Secure behavior",
failure_condition="Insecure behavior",
)

def test_secret_executor_detects_hardcoded_secret(
tmp_path: Path,
):
"""Secret regression should detect a synthetic hardcoded secret."""
source_root = tmp_path / "app"
source_root.mkdir()


source_file = source_root / "example.py"

source_file.write_text(
    'LAB_API_KEY = "sk-lab-example-123456789"\n',
    encoding="utf-8",
)

executor = SecureCommerceRegressionExecutor(
    source_root=source_root
)

result = executor.execute(
    build_test(
        "SECRET-001",
        requirement="SF-SECRET-001",
    )
)

assert result["status"] == "failed"
assert "detected" in (
    result["actual_result"]
)

matches = result["evidence"]["matches"]

assert len(matches) == 1
assert matches[0]["value"] == "[REDACTED]"
assert matches[0]["line"] == 1


def test_secret_executor_passes_clean_source(
tmp_path: Path,
):
"""Secret regression should pass when no secret is present."""
source_root = tmp_path / "app"
source_root.mkdir()


source_file = source_root / "example.py"

source_file.write_text(
    """


def health():
return "ok"
""",
encoding="utf-8",
)


executor = SecureCommerceRegressionExecutor(
    source_root=source_root
)

result = executor.execute(
    build_test(
        "SECRET-001",
        requirement="SF-SECRET-001",
    )
)

assert result["status"] == "passed"
assert result["evidence"]["matches"] == []


def test_iac_executor_passes_secure_configuration(
tmp_path: Path,
):
"""IaC regression should pass secure infrastructure configuration."""
infrastructure_root = tmp_path / "infra"
infrastructure_root.mkdir()


secure_file = (
    infrastructure_root
    / "secure.tf"
)

secure_file.write_text(
    """


resource "null_resource" "secure_application" {
triggers = {
host = "127.0.0.1"
port = "5000"
}
}

resource "null_resource" "encrypted_storage" {
triggers = {
encryption = "enabled"
access     = "private"
}
}

resource "null_resource" "least_privilege_role" {
triggers = {
permissions = "read-write-required-resources-only"
}
}
""",
encoding="utf-8",
)


executor = SecureCommerceRegressionExecutor(
    infrastructure_root=infrastructure_root
)

result = executor.execute(
    build_test(
        "MISCONFIG-001",
        requirement="SF-IAC-001",
    )
)

assert result["status"] == "passed"

checks = result["evidence"]["checks"]

assert all(checks.values())


def test_iac_executor_fails_insecure_configuration(
tmp_path: Path,
):
"""IaC regression should detect insecure infrastructure."""
infrastructure_root = tmp_path / "infra"
infrastructure_root.mkdir()


secure_file = (
    infrastructure_root
    / "secure.tf"
)

secure_file.write_text(
    """


resource "null_resource" "insecure" {
triggers = {
host        = "0.0.0.0"
encryption  = "disabled"
access      = "public"
permissions = "*"
}
}
""",
encoding="utf-8",
)


executor = SecureCommerceRegressionExecutor(
    infrastructure_root=infrastructure_root
)

result = executor.execute(
    build_test(
        "MISCONFIG-001",
        requirement="SF-IAC-001",
    )
)

assert result["status"] == "failed"

checks = result["evidence"]["checks"]

assert checks["localhost_binding"] is False
assert checks["encryption_enabled"] is False
assert checks["private_storage"] is False
assert checks["least_privilege"] is False
assert checks["wildcard_permissions_absent"] is False


def test_executor_rejects_unknown_test():
"""Unknown regression IDs should be rejected."""
executor = SecureCommerceRegressionExecutor()


result = None

try:
    executor.execute(
        build_test(
            "UNKNOWN-001"
        )
    )
except Exception as exc:
    result = exc

assert result is not None
assert "No SecureCommerce regression executor" in str(
    result
)


def test_secret_executor_requires_source_root():
"""Secret scanning should require a source directory."""
executor = SecureCommerceRegressionExecutor()


try:
    executor.execute(
        build_test(
            "SECRET-001",
            requirement="SF-SECRET-001",
        )
    )
except Exception as exc:
    error = exc
else:
    error = None

assert error is not None
assert "source_root is required" in str(error)


def test_iac_executor_requires_infrastructure_root():
"""IaC scanning should require an infrastructure directory."""
executor = SecureCommerceRegressionExecutor()


try:
    executor.execute(
        build_test(
            "MISCONFIG-001",
            requirement="SF-IAC-001",
        )
    )
except Exception as exc:
    error = exc
else:
    error = None

assert error is not None
assert "infrastructure_root is required" in str(error)

