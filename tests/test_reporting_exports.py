"""Tests for SecureForge reporting package exports."""

from **future** import annotations

import secureforge.reporting as reporting

def test_reporting_package_exports_models():
"""Reporting package should expose report models."""
assert hasattr(
reporting,
"SecurityReport",
)
assert hasattr(
reporting,
"ReportFinding",
)
assert hasattr(
reporting,
"RiskReport",
)
assert hasattr(
reporting,
"PolicyReport",
)
assert hasattr(
reporting,
"DecisionReport",
)

def test_reporting_package_exports_regression_models():
"""Reporting package should expose regression report models."""
assert hasattr(
reporting,
"RegressionReport",
)
assert hasattr(
reporting,
"RegressionTestReport",
)

def test_reporting_package_exports_regression_builder():
"""Reporting package should expose the regression adapter."""
assert hasattr(
reporting,
"build_regression_report",
)
assert callable(
reporting.build_regression_report
)

def test_reporting_package_exports_builders():
"""Reporting package should expose core reporting builders."""
assert hasattr(
reporting,
"SecurityReportBuilder",
)
assert hasattr(
reporting,
"SecurityReportSerializer",
)
assert hasattr(
reporting,
"SecurityHTMLReportRenderer",
)
assert hasattr(
reporting,
"SecurityReportService",
)

def test_reporting_package_defines_public_api():
"""All expected public names should be listed in **all**."""
expected = {
"DecisionReport",
"PolicyReport",
"RegressionReport",
"RegressionTestReport",
"ReleaseMetadata",
"RemediationReport",
"ReportFinding",
"ReportPaths",
"RiskReport",
"ScanMetadata",
"SecurityHTMLReportRenderer",
"SecurityReport",
"SecurityReportBuilder",
"SecurityReportSerializer",
"SecurityReportService",
"build_regression_report",
}

```
assert set(
    reporting.__all__
) == expected
```
