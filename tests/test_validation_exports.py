```python id="4t7m2c"
"""Tests for SecureForge validation package exports."""

import secureforge.validation as validation


def test_validation_package_exports_core_models() -> None:
    assert hasattr(validation, "ValidationEvidence")
    assert hasattr(validation, "ValidationMethod")
    assert hasattr(validation, "ValidationOutcome")
    assert hasattr(validation, "ValidationRequest")
    assert hasattr(validation, "ValidationResult")
    assert hasattr(validation, "ValidationSummary")
    assert hasattr(validation, "RetestResult")


def test_validation_package_exports_validators() -> None:
    assert hasattr(validation, "HTTPValidator")
    assert hasattr(validation, "APIValidator")
    assert hasattr(validation, "CommandValidator")
    assert hasattr(validation, "ScriptValidator")
    assert hasattr(validation, "ManualValidator")


def test_validation_package_exports_services() -> None:
    assert hasattr(validation, "ValidationEngine")
    assert hasattr(validation, "ValidationService")
    assert hasattr(validation, "RetestService")


def test_validation_package_exports_registry() -> None:
    assert hasattr(validation, "ValidatorRegistry")
    assert hasattr(validation, "ValidatorRegistryError")


def test_validation_package_exports_factory_helpers() -> None:
    assert hasattr(validation, "build_validation_registry")
    assert hasattr(validation, "build_validation_engine")


def test_validation_package_defines_public_api() -> None:
    expected = {
        "APIValidator",
        "BaseValidator",
        "CommandValidator",
        "HTTPValidator",
        "ManualValidator",
        "RetestResult",
        "RetestService",
        "ScriptValidator",
        "ValidationEngine",
        "ValidationError",
        "ValidationEvidence",
        "ValidationMethod",
        "ValidationOutcome",
        "ValidationRequest",
        "ValidationResult",
        "ValidationService",
        "ValidationSummary",
        "ValidatorRegistry",
        "ValidatorRegistryError",
        "build_validation_engine",
        "build_validation_registry",
    }

    assert set(validation.__all__) == expected
```
