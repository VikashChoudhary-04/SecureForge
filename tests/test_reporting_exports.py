"""Tests for the public SecureForge reporting package API."""

from **future** import annotations

import secureforge.reporting as reporting

def test_reporting_package_exports_builder():
"""SecurityReportBuilder should be publicly available."""
assert hasattr(
reporting,
"SecurityReportBuilder",
)

def test_reporting_package_exports_models():
"""Core reporting models should be publicly available."""
exported_models = {
"DecisionReport",
"PolicyReport",
"RegressionReport",
"RegressionTestReport",
"ReleaseMetadata",
"RemediationReport",
"ReportFinding",
"RiskReport",
"ScanMetadata",
"SecurityReport",
}

```
for model_name in exported_models:
    assert hasattr(
        reporting,
        model_name,
    )
```

def test_reporting_package_exports_rendering():
"""HTML and JSON reporting components should be public."""
assert hasattr(
reporting,
"SecurityHTMLReportRenderer",
)
assert hasattr(
reporting,
"SecurityReportSerializer",
)

def test_reporting_package_exports_service():
"""The high-level reporting service should be public."""
assert hasattr(
reporting,
"SecurityReportService",
)
assert hasattr(
reporting,
"ReportPaths",
)

def test_reporting_all_contains_public_api():
"""The package **all** should describe the public reporting API."""
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
}

```
assert set(reporting.__all__) == expected
```
