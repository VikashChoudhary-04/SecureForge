"""HTML renderer for SecureForge security reports."""

from **future** import annotations

from html import escape
from pathlib import Path

from .models import SecurityReport

class SecurityHTMLReportRenderer:
"""Render SecureForge security reports as HTML."""

```
def render(
    self,
    report: SecurityReport,
) -> str:
    """Render a complete security report as HTML."""
    return f"""<!DOCTYPE html>
```

<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecureForge Security Report</title>
<style>
body {{
    font-family: Arial, sans-serif;
    line-height: 1.5;
    margin: 0;
    padding: 0;
    background: #f5f5f5;
    color: #222;
}}
main {{
    max-width: 1200px;
    margin: 0 auto;
    padding: 32px;
}}
section {{
    background: #fff;
    margin-bottom: 24px;
    padding: 24px;
    border: 1px solid #ddd;
    border-radius: 8px;
}}
h1, h2 {{
    margin-top: 0;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 16px;
}}
th, td {{
    text-align: left;
    padding: 10px;
    border-bottom: 1px solid #ddd;
    vertical-align: top;
}}
th {{
    background: #f0f0f0;
}}
pre {{
    white-space: pre-wrap;
    word-break: break-word;
    background: #f5f5f5;
    padding: 12px;
    border-radius: 4px;
}}
.status {{
    font-weight: bold;
}}
.finding {{
    margin-bottom: 24px;
    padding-bottom: 24px;
    border-bottom: 1px solid #ddd;
}}
.finding:last-child {{
    border-bottom: none;
}}
ul {{
    padding-left: 24px;
}}
code {{
    font-family: Consolas, monospace;
}}
</style>
</head>
<body>
<main>
{self._render_header(report)}
{self._render_release(report)}
{self._render_scan(report)}
{self._render_decision(report)}
{self._render_regression_gate(report)}
{self._render_risk(report)}
{self._render_policy(report)}
{self._render_findings(report)}
{self._render_remediation(report)}
{self._render_regression(report)}
{self._render_footer(report)}
</main>
</body>
</html>
"""

```
def write_html(
    self,
    report: SecurityReport,
    path: Path,
) -> None:
    """Write a security report to an HTML file."""
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        self.render(report),
        encoding="utf-8",
    )

@staticmethod
def _render_header(
    report: SecurityReport,
) -> str:
    """Render the report header."""
    return f"""
```

<section>
<h1>SecureForge Security Report</h1>
<p>
<strong>Application:</strong>
{escape(report.release.application)}
</p>
<p>
<strong>Release:</strong>
{escape(report.release.release_id)}
</p>
<p>
<strong>Decision:</strong>
<span class="status">
{escape(report.decision.status)}
</span>
</p>
</section>
"""

```
@staticmethod
def _render_release(
    report: SecurityReport,
) -> str:
    """Render release metadata."""
    release = report.release

    return f"""
```

<section>
<h2>Release Metadata</h2>
<table>
<tr>
<th>Field</th>
<th>Value</th>
</tr>
<tr>
<td>Release ID</td>
<td>{escape(release.release_id)}</td>
</tr>
<tr>
<td>Application</td>
<td>{escape(release.application)}</td>
</tr>
<tr>
<td>Version</td>
<td>{escape(release.version)}</td>
</tr>
<tr>
<td>Commit SHA</td>
<td>{escape(release.commit_sha)}</td>
</tr>
<tr>
<td>Environment</td>
<td>{escape(release.environment)}</td>
</tr>
<tr>
<td>Timestamp</td>
<td>{escape(release.timestamp)}</td>
</tr>
</table>
</section>
"""

```
@staticmethod
def _render_scan(
    report: SecurityReport,
) -> str:
    """Render scan metadata."""
    scan = report.scan

    tools = "".join(
        f"<li>{escape(tool)}</li>"
        for tool in scan.tools
    )

    return f"""
```

<section>
<h2>Scan Metadata</h2>
<table>
<tr>
<th>Field</th>
<th>Value</th>
</tr>
<tr>
<td>Scan ID</td>
<td>{escape(scan.scan_id)}</td>
</tr>
<tr>
<td>Profile</td>
<td>{escape(scan.profile)}</td>
</tr>
<tr>
<td>Status</td>
<td>{escape(scan.status)}</td>
</tr>
<tr>
<td>Started At</td>
<td>{escape(scan.started_at)}</td>
</tr>
<tr>
<td>Completed At</td>
<td>{escape(scan.completed_at)}</td>
</tr>
<tr>
<td>Duration</td>
<td>{escape(str(scan.duration_seconds))} seconds</td>
</tr>
</table>

<h3>Tools</h3>
<ul>
{tools if tools else "<li>None</li>"}
</ul>
</section>
"""

```
@staticmethod
def _render_decision(
    report: SecurityReport,
) -> str:
    """Render the final release decision."""
    decision = report.decision

    return f"""
```

<section>
<h2>Release Decision</h2>
<table>
<tr>
<th>Field</th>
<th>Value</th>
</tr>
<tr>
<td>Status</td>
<td class="status">{escape(decision.status)}</td>
</tr>
<tr>
<td>Reason</td>
<td>{escape(decision.reason)}</td>
</tr>
<tr>
<td>Release Allowed</td>
<td>{escape(str(decision.release_allowed))}</td>
</tr>
</table>
</section>
"""

```
@staticmethod
def _render_regression_gate(
    report: SecurityReport,
) -> str:
    """Render the regression-specific release-gate decision."""
    gate = report.regression_gate

    if gate is None:
        return """
```

<section>
<h2>Regression Gate</h2>
<p>No regression-gate decision was recorded.</p>
</section>
"""

```
    failed_tests = "".join(
        f"<li>{escape(test_id)}</li>"
        for test_id in gate.failed_tests
    )

    errored_tests = "".join(
        f"<li>{escape(test_id)}</li>"
        for test_id in gate.errored_tests
    )

    skipped_tests = "".join(
        f"<li>{escape(test_id)}</li>"
        for test_id in gate.skipped_tests
    )

    failures = "".join(
        f"<li>{escape(failure)}</li>"
        for failure in gate.failures
    )

    return f"""
```

<section>
<h2>Regression Gate</h2>

<table>
<tr>
<th>Field</th>
<th>Value</th>
</tr>
<tr>
<td>Status</td>
<td class="status">{escape(gate.status)}</td>
</tr>
<tr>
<td>Allowed</td>
<td>{escape(str(gate.allowed))}</td>
</tr>
<tr>
<td>Blocked</td>
<td>{escape(str(gate.blocked))}</td>
</tr>
<tr>
<td>Reason</td>
<td>{escape(gate.reason)}</td>
</tr>
</table>

<h3>Failed Tests</h3>
<ul>
{failed_tests if failed_tests else "<li>None</li>"}
</ul>

<h3>Errored Tests</h3>
<ul>
{errored_tests if errored_tests else "<li>None</li>"}
</ul>

<h3>Skipped Tests</h3>
<ul>
{skipped_tests if skipped_tests else "<li>None</li>"}
</ul>

<h3>Regression Failures</h3>
<ul>
{failures if failures else "<li>None</li>"}
</ul>
</section>
"""

```
@staticmethod
def _render_risk(
    report: SecurityReport,
) -> str:
    """Render risk assessment."""
    risk = report.risk

    factors = "".join(
        f"<li>{escape(str(factor))}</li>"
        for factor in risk.factors
    )

    return f"""
```

<section>
<h2>Risk Assessment</h2>
<table>
<tr>
<th>Field</th>
<th>Value</th>
</tr>
<tr>
<td>Risk Score</td>
<td>{escape(str(risk.score))}</td>
</tr>
<tr>
<td>Highest Severity</td>
<td>{escape(risk.highest_severity)}</td>
</tr>
<tr>
<td>Confirmed Critical</td>
<td>{escape(str(risk.confirmed_critical))}</td>
</tr>
<tr>
<td>Confirmed High</td>
<td>{escape(str(risk.confirmed_high))}</td>
</tr>
</table>

<h3>Risk Factors</h3>
<ul>
{factors if factors else "<li>None</li>"}
</ul>
</section>
"""

```
@staticmethod
def _render_policy(
    report: SecurityReport,
) -> str:
    """Render policy evaluation."""
    policy = report.policy

    actions = "".join(
        f"<li>{escape(str(action))}</li>"
        for action in policy.actions
    )

    exceptions = "".join(
        f"<li>{escape(str(exception))}</li>"
        for exception in policy.exceptions
    )

    tool_errors = "".join(
        f"<li>{escape(error)}</li>"
        for error in policy.tool_errors
    )

    regression_failures = "".join(
        f"<li>{escape(failure)}</li>"
        for failure in policy.regression_failures
    )

    return f"""
```

<section>
<h2>Policy Evaluation</h2>
<p>
<strong>Policy:</strong>
{escape(policy.policy_name)}
</p>

<h3>Actions</h3>
<ul>
{actions if actions else "<li>None</li>"}
</ul>

<h3>Tool Errors</h3>
<ul>
{tool_errors if tool_errors else "<li>None</li>"}
</ul>

<h3>Regression Failures</h3>
<ul>
{regression_failures
    if regression_failures
    else "<li>None</li>"}
</ul>

<h3>Exceptions</h3>
<ul>
{exceptions if exceptions else "<li>None</li>"}
</ul>
</section>
"""

```
@staticmethod
def _render_findings(
    report: SecurityReport,
) -> str:
    """Render security findings."""
    if not report.findings:
        return """
```

<section>
<h2>Findings</h2>
<p>No findings were recorded.</p>
</section>
"""

```
    findings = []

    for finding in report.findings:
        evidence_items = "".join(
            f"<li>{escape(str(evidence))}</li>"
            for evidence in finding.evidence
        )

        correlations = "".join(
            f"<li>{escape(correlation)}</li>"
            for correlation in finding.correlations
        )

        findings.append(
            f"""
```

<div class="finding">
<h3>
{escape(finding.finding_id)}
:
{escape(finding.title)}
</h3>

<table>
<tr>
<th>Field</th>
<th>Value</th>
</tr>
<tr>
<td>Source</td>
<td>{escape(finding.source)}</td>
</tr>
<tr>
<td>Asset</td>
<td>{escape(finding.asset)}</td>
</tr>
<tr>
<td>Application</td>
<td>{escape(finding.application or "")}</td>
</tr>
<tr>
<td>Endpoint</td>
<td>{escape(finding.endpoint or "")}</td>
</tr>
<tr>
<td>Parameter</td>
<td>{escape(finding.parameter or "")}</td>
</tr>
<tr>
<td>Severity</td>
<td>{escape(finding.severity)}</td>
</tr>
<tr>
<td>Confidence</td>
<td>{escape(finding.confidence)}</td>
</tr>
<tr>
<td>Status</td>
<td>{escape(finding.status)}</td>
</tr>
<tr>
<td>Validation Status</td>
<td>{escape(finding.validation_status)}</td>
</tr>
<tr>
<td>CWE</td>
<td>{escape(finding.cwe or "")}</td>
</tr>
<tr>
<td>OWASP Mapping</td>
<td>{escape(finding.owasp_mapping or "")}</td>
</tr>
<tr>
<td>Security Requirement</td>
<td>{escape(finding.security_requirement or "")}</td>
</tr>
<tr>
<td>Regression Test</td>
<td>{escape(finding.regression_test or "")}</td>
</tr>
</table>

<h4>Description</h4>
<p>{escape(finding.description)}</p>

<h4>Impact</h4>
<p>{escape(finding.impact)}</p>

<h4>Remediation</h4>
<p>{escape(finding.remediation)}</p>

<h4>Evidence</h4>
<ul>
{evidence_items if evidence_items else "<li>None</li>"}
</ul>

<h4>Correlations</h4>
<ul>
{correlations if correlations else "<li>None</li>"}
</ul>
</div>
"""
            )

```
    return f"""
```

<section>
<h2>Findings</h2>
{''.join(findings)}
</section>
"""

```
@staticmethod
def _render_remediation(
    report: SecurityReport,
) -> str:
    """Render remediation information."""
    remediation = report.remediation

    items = "".join(
        f"<li>{escape(str(item))}</li>"
        for item in remediation.items
    )

    return f"""
```

<section>
<h2>Remediation</h2>
<table>
<tr>
<th>Metric</th>
<th>Count</th>
</tr>
<tr>
<td>Total</td>
<td>{escape(str(remediation.total))}</td>
</tr>
<tr>
<td>Open</td>
<td>{escape(str(remediation.open))}</td>
</tr>
<tr>
<td>In Progress</td>
<td>{escape(str(remediation.in_progress))}</td>
</tr>
<tr>
<td>Resolved</td>
<td>{escape(str(remediation.resolved))}</td>
</tr>
<tr>
<td>Verified</td>
<td>{escape(str(remediation.verified))}</td>
</tr>
</table>

<h3>Items</h3>
<ul>
{items if items else "<li>None</li>"}
</ul>
</section>
"""

```
@staticmethod
def _render_regression(
    report: SecurityReport,
) -> str:
    """Render regression testing results."""
    regression = report.regression

    tests = []

    for test in regression.tests:
        evidence = escape(
            str(test.evidence)
        )

        tests.append(
            f"""
```

<tr>
<td>{escape(test.test_id)}</td>
<td>{escape(test.status)}</td>
<td>{escape(test.expected)}</td>
<td>{escape(test.actual)}</td>
<td>{escape(test.message)}</td>
<td><pre>{evidence}</pre></td>
</tr>
"""
            )

```
    return f"""
```

<section>
<h2>Regression Testing</h2>

<table>
<tr>
<th>Field</th>
<th>Value</th>
</tr>
<tr>
<td>Suite ID</td>
<td>{escape(regression.suite_id)}</td>
</tr>
<tr>
<td>Suite Name</td>
<td>{escape(regression.suite_name)}</td>
</tr>
<tr>
<td>Status</td>
<td>{escape(regression.status)}</td>
</tr>
<tr>
<td>Total</td>
<td>{escape(str(regression.total))}</td>
</tr>
<tr>
<td>Passed</td>
<td>{escape(str(regression.passed))}</td>
</tr>
<tr>
<td>Failed</td>
<td>{escape(str(regression.failed))}</td>
</tr>
<tr>
<td>Errors</td>
<td>{escape(str(regression.errors))}</td>
</tr>
<tr>
<td>Skipped</td>
<td>{escape(str(regression.skipped))}</td>
</tr>
<tr>
<td>Started At</td>
<td>{escape(regression.started_at or "")}</td>
</tr>
<tr>
<td>Completed At</td>
<td>{escape(regression.completed_at or "")}</td>
</tr>
<tr>
<td>Duration</td>
<td>{escape(str(regression.duration_seconds))} seconds</td>
</tr>
</table>

<h3>Tests</h3>

<table>
<tr>
<th>Test ID</th>
<th>Status</th>
<th>Expected</th>
<th>Actual</th>
<th>Message</th>
<th>Evidence</th>
</tr>
{''.join(tests) if tests else """
<tr>
<td colspan="6">No regression tests were executed.</td>
</tr>
"""}
</table>
</section>
"""

```
@staticmethod
def _render_footer(
    report: SecurityReport,
) -> str:
    """Render report generation metadata."""
    return f"""
```

<section>
<h2>Report Metadata</h2>
<p>
<strong>Generated At:</strong>
{escape(report.generated_at)}
</p>
</section>
"""
