```python id="m7q2v9"
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


def test_validation_package_exports_engine_and_services() -> None:
    assert hasattr(validation, "ValidationEngine")
    assert hasattr(validation, "ValidationService")
    assert hasattr(validation, "ValidationRunner")
    assert hasattr(validation, "RetestService")
    assert hasattr(validation, "ValidationRun")
    assert hasattr(validation, "RetestRun")


def test_validation_package_exports_registry() -> None:
    assert hasattr(validation, "ValidatorRegistry")
    assert hasattr(validation, "ValidatorRegistryError")


def test_validation_package_exports_assessment() -> None:
    assert hasattr(validation, "ValidationAssessment")
    assert hasattr(validation, "assess_validation")
    assert hasattr(validation, "assess_many")


def test_validation_package_exports_integration() -> None:
    assert hasattr(validation, "FindingValidationUpdate")
    assert hasattr(validation, "apply_validation_result")
    assert hasattr(validation, "apply_validation_results")


def test_validation_package_exports_gate() -> None:
    assert hasattr(validation, "ValidationGateDecision")
    assert hasattr(validation, "evaluate_validation_run")
    assert hasattr(validation, "evaluate_retest_run")


def test_validation_package_exports_serialization() -> None:
    assert hasattr(validation, "validation_result_to_dict")
    assert hasattr(validation, "validation_summary_to_dict")
    assert hasattr(validation, "retest_result_to_dict")
    assert hasattr(validation, "assessment_to_dict")
    assert hasattr(validation, "gate_decision_to_dict")
    assert hasattr(validation, "dumps_validation_result")
    assert hasattr(validation, "dumps_validation_summary")
    assert hasattr(validation, "dumps_retest_result")


def test_validation_package_exports_factory_helpers() -> None:
    assert hasattr(validation, "build_validation_registry")
    assert hasattr(validation, "build_validation_engine")


def test_validation_package_defines_complete_public_api() -> None:
    expected = {
        "APIValidator",
        "BaseValidator",
        "CommandValidator",
        "FindingValidationUpdate",
        "HTTPValidator",
        "ManualValidator",
        "RetestResult",
        "RetestRun",
        "RetestService",
        "ScriptValidator",
        "ValidationAssessment",
        "ValidationEngine",
        "ValidationError",
        "ValidationEvidence",
        "ValidationGateDecision",
        "ValidationMethod",
        "ValidationOutcome",
        "ValidationRequest",
        "ValidationResult",
        "ValidationRun",
        "ValidationRunner",
        "ValidationService",
        "ValidationSummary",
        "ValidatorRegistry",
        "ValidatorRegistryError",
        "apply_validation_result",
        "apply_validation_results",
        "assess_many",
        "assess_validation",
        "assessment_to_dict",
        "build_validation_engine",
        "build_validation_registry",
        "dumps_retest_result",
        "dumps_validation_result",
        "dumps_validation_summary",
        "evaluate_retest_run",
        "evaluate_validation_run",
        "gate_decision_to_dict",
        "retest_result_to_dict",
        "validation_result_to_dict",
        "validation_summary_to_dict",
    }

    assert set(validation.__all__) == expected
```
