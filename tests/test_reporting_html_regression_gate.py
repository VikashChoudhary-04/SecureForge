"""Tests for regression-gate rendering in HTML security reports."""

from secureforge.regression import (
RegressionGateDecision,
)
from secureforge.reporting import (
SecurityHTMLReportRenderer,
SecurityReportBuilder,
)

def test_html_renderer_includes_regression_gate(
sample_release,
sample_scan,
sample_findings,
sample_risk,
sample_policy,
sample_decision,
) -> None:
"""Render the regression-gate decision in the HTML report."""
regression_gate = RegressionGateDecision(
allowed=False,
status="failed",
reason=(
"One or more security regression tests failed."
),
failed_tests=(
"BOLA-001",
"SQLI-001",
),
errored_tests=(
"AUTHZ-001",
),
skipped_tests=(
"OPTIONAL-001",
),
)

```
report = SecurityReportBuilder().build(
    release=sample_release,
    scan=sample_scan,
    findings=sample_findings,
    risk=sample_risk,
    policy=sample_policy,
    decision=sample_decision,
    regression_gate=regression_gate,
)

html = SecurityHTMLReportRenderer().render(
    report
)

assert "<h2>Regression Gate</h2>" in html
assert "failed" in html
assert "BOLA-001" in html
assert "SQLI-001" in html
assert "AUTHZ-001" in html
assert "OPTIONAL-001" in html
assert (
    "One or more security regression tests failed."
    in html
)
```

def test_html_renderer_escapes_regression_gate_values(
sample_release,
sample_scan,
sample_findings,
sample_risk,
sample_policy,
sample_decision,
) -> None:
"""Escape untrusted regression-gate values in HTML."""
regression_gate = RegressionGateDecision(
allowed=False,
status="<failed>",
reason="<script>alert('x')</script>",
failed_tests=(
"<BOLA-001>",
),
errored_tests=(),
skipped_tests=(),
)

```
report = SecurityReportBuilder().build(
    release=sample_release,
    scan=sample_scan,
    findings=sample_findings,
    risk=sample_risk,
    policy=sample_policy,
    decision=sample_decision,
    regression_gate=regression_gate,
)

html = SecurityHTMLReportRenderer().render(
    report
)

assert "<failed>" not in html
assert "&lt;failed&gt;" in html
assert "<script>alert('x')</script>" not in html
assert (
    "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;"
    in html
)
assert "<BOLA-001>" not in html
assert "&lt;BOLA-001&gt;" in html
```

def test_html_renderer_handles_missing_regression_gate(
sample_release,
sample_scan,
sample_findings,
sample_risk,
sample_policy,
sample_decision,
) -> None:
"""Render a clear message when no regression gate exists."""
report = SecurityReportBuilder().build(
release=sample_release,
scan=sample_scan,
findings=sample_findings,
risk=sample_risk,
policy=sample_policy,
decision=sample_decision,
)

```
html = SecurityHTMLReportRenderer().render(
    report
)

assert "<h2>Regression Gate</h2>" in html
assert (
    "No regression-gate decision was recorded."
    in html
)
```
