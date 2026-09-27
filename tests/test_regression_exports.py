"""Tests for the SecureForge regression package exports."""

from **future** import annotations

import secureforge.regression as regression

def test_regression_package_exports_core_components():
"""Regression package should expose core components."""
assert hasattr(
regression,
"RegressionEngine",
)
assert hasattr(
regression,
"RegressionLoader",
)
assert hasattr(
regression,
"RegressionRegistry",
)
assert hasattr(
regression,
"RegressionTest",
)
assert hasattr(
regression,
"RegressionSuite",
)
assert hasattr(
regression,
"RegressionSuiteResult",
)

def test_regression_package_exports_execution_components():
"""Regression package should expose execution components."""
assert hasattr(
regression,
"RegressionRunner",
)
assert hasattr(
regression,
"RegressionRunConfiguration",
)
assert hasattr(
regression,
"RegressionService",
)
assert hasattr(
regression,
"RegressionServiceConfiguration",
)
assert hasattr(
regression,
"SecureCommerceRegressionExecutor",
)

def test_regression_package_exports_assessment_components():
"""Regression package should expose assessment components."""
assert hasattr(
regression,
"RegressionAssessment",
)
assert hasattr(
regression,
"assess_regression_result",
)

def test_regression_package_exports_gate_integration():
"""Regression package should expose release-gate integration."""
assert hasattr(
regression,
"RegressionGateInput",
)
assert hasattr(
regression,
"build_regression_gate_input",
)
assert hasattr(
regression,
"build_regression_gate_input_from_assessment",
)

def test_regression_package_exports_builders():
"""Regression package should expose default builders."""
assert callable(
regression.build_regression_runner
)
assert callable(
regression.build_regression_service
)
assert callable(
regression.build_securecommerce_executor
)

def test_regression_package_exports_cli():
"""Regression package should expose its CLI application."""
assert hasattr(
regression,
"regression_app",
)

def test_regression_package_defines_public_api():
"""All expected public names should be listed in **all**."""
expected = {
"RegressionAssessment",
"RegressionConfigurationError",
"RegressionEngine",
"RegressionExecutionError",
"RegressionExecutorError",
"RegressionGateInput",
"RegressionLoader",
"RegressionRegistry",
"RegressionRegistryError",
"RegressionResult",
"RegressionRunConfiguration",
"RegressionRunner",
"RegressionService",
"RegressionServiceConfiguration",
"RegressionStatus",
"RegressionSuite",
"RegressionSuiteResult",
"RegressionTest",
"RegressionTestNotFoundError",
"SecureCommerceRegressionExecutor",
"assess_regression_result",
"build_regression_gate_input",
"build_regression_gate_input_from_assessment",
"build_regression_runner",
"build_regression_service",
"build_securecommerce_executor",
"regression_app",
}

```
assert set(
    regression.__all__
) == expected
```
