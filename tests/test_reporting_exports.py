"""Tests for SecureForge reporting package exports."""

from secureforge.reporting import (
RegressionGateReport,
RegressionReport,
RegressionTestReport,
SecurityReportBuilder,
SecurityHTMLReportRenderer,
SecurityReportSerializer,
SecurityReportService,
build_regression_gate_report,
build_regression_report,
)

def test_reporting_exports() -> None:
"""Verify the public reporting API exports."""
assert SecurityReportBuilder is not None
assert SecurityHTMLReportRenderer is not None
assert SecurityReportSerializer is not None
assert SecurityReportService is not None

```
assert RegressionReport is not None
assert RegressionTestReport is not None
assert RegressionGateReport is not None

assert build_regression_report is not None
assert build_regression_gate_report is not None
```
