"""HTML security report rendering for SecureForge."""

from **future** import annotations

from html import escape
from pathlib import Path

from .models import SecurityReport

class SecurityHTMLReportRenderer:
"""Render a SecureForge security report as HTML."""

```
def render(
    self,
    report: SecurityReport,
) -> str:
    """Render the complete security report."""
    findings_html = self._render_findings(
        report
    )
    remediation_html = (
        self._render_remediation(
            report
        )
    )
    regression_html = (
        self._render_regression(
            report
        )
    )
    policy_html = self._render_policy(
        report
    )
    tool_errors_html = (
        self._render_tool_errors(
            report
        )
    )

    return f"""<!DOCTYPE html>
```

<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport"
      content="width=device-width, initial-scale=1">
<title>SecureForge Security Report</title>
<style>
body {{
    font-family: Arial, sans-serif;
    margin: 0;
    padding: 0;
    background: #f5f7fa;
    color: #1f2937;
}}
.container {{
    max-width: 1200px;
    margin: 0 auto;
    padding: 32px;
}}
header {{
    background: #111827;
    color: white;
    padding: 28px;
    border-radius: 10px;
    margin-bottom: 24px;
}}
h1, h2 {{
    margin-top: 0;
}}
section {{
    background: white;
    padding: 24px;
    border-radius: 10px;
    margin-bottom: 20px;
    box-shadow: 0 1px 3px rgba(0,0,0,.08);
}}
.grid {{
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
}}
.card {{
    background: #f9fafb;
    padding: 16px;
    border-radius: 8px;
}}
.label {{
    font-size: 12px;
    color: #6b7280;
    text-transform: uppercase;
}}
.value {{
    font-size: 22px;
    font-weight: bold;
    margin-top: 6px;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 12px;
}}
th, td {{
    padding: 10px;
    border-bottom: 1px solid #e5e7eb;
    text-align: left;
    vertical-align: top;
}}
th {{
    background: #f9fafb;
}}
.status {{
    font-weight: bold;
}}
pre {{
    white-space: pre-wrap;
    word-break: break-word;
}}
.small {{
    color: #6b7280;
    font-size: 13px;
}}
</style>
</head>
<body>
<div class="container">

<header>
    <h1>SecureForge Security Report</h1>
    <p>
        Release:
        {escape(str(report.release.release_id))}
    </p>
    <p>
        Decision:
        <strong>
            {escape(str(report.decision.status))}
        </strong>
    </p>
    <p>
        Generated:
        {escape(str(report.generated_at))}
    </p>
</header>

<section>
    <h2>Release Metadata</h2>
    <div class="grid">
        <div class="card">
            <div class="label">Application</div>
            <div class="value">
                {escape(str(report.release.application))}
            </div>
        </div>
        <div class="card">
            <div class="label">Version</div>
            <div class="value">
                {escape(str(report.release.version))}
            </div>
        </div>
        <div class="card">
            <div class="label">Commit</div>
            <div class="value">
                {escape(str(report.release.commit_sha))}
            </div>
        </div>
        <div class="card">
            <div class="label">Environment</div>
            <div class="value">
                {escape(str(report.release.environment))}
            </div>
        </div>
    </div>
</section>

<section>
    <h2>Scan Summary</h2>
    <div class="grid">
        <div class="card">
            <div class="label">Profile</div>
            <div class="value">
                {escape(str(report.scan.profile))}
            </div>
        </div>
        <div class="card">
            <div class="label">Status</div>
            <div class="value">
                {escape(str(report.scan.status))}
            </div>
        </div>
        <div class="card">
            <div class="label">Findings</div>
            <div class="value">
                {len(report.findings)}
            </div>
        </div>
        <div class="card">
            <div class="label">Duration</div>
            <div class="value">
                {escape(str(report.scan.duration_seconds))}s
            </div>
        </div>
    </div>
</section>

<section>
    <h2>Risk Assessment</h2>
    <div class="grid">
        <div class="card">
            <div class="label">Risk Score</div>
            <div class="value">
                {escape(str(report.risk.score))}
            </div>
        </div>
        <div class="card">
            <div class="label">Highest Severity</div>
            <div class="value">
                {escape(
                    str(report.risk.highest_severity)
                )}
            </div>
        </div>
        <div class="card">
            <div class="label">Confirmed Critical</div>
            <div class="value">
                {escape(
                    str(report.risk.confirmed_critical)
                )}
            </div>
        </div>
        <div class="card">
            <div class="label">Confirmed High</div>
            <div class="value">
                {escape(
                    str(report.risk.confirmed_high)
                )}
            </div>
        </div>
    </div>
</section>

<section>
    <h2>Findings</h2>
    {findings_html}
</section>

<section>
    <h2>Remediation</h2>
    {remediation_html}
</section>

<section>
    <h2>Regression Testing</h2>
    {regression_html}
</section>

<section>
    <h2>Policy Evaluation</h2>
    {policy_html}
</section>

<section>
    <h2>Release Decision</h2>
    <p class="status">
        Status:
        {escape(str(report.decision.status))}
    </p>
    <p>
        Reason:
        {escape(str(report.decision.reason))}
    </p>
    <p>
        Release allowed:
        {escape(
            str(report.decision.release_allowed)
        )}
    </p>
</section>

<section>
    <h2>Tool Errors</h2>
    {tool_errors_html}
</section>

</div>
</body>
</html>
"""

```
def write_html(
    self,
    report: SecurityReport,
    path: str | Path,
) -> Path:
    """Render and write the report to an HTML file."""
    output_path = Path(path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        self.render(report),
        encoding="utf-8",
    )

    return output_path

@staticmethod
def _render_findings(
    report: SecurityReport,
) -> str:
    """Render findings as an HTML table."""
    if not report.findings:
        return "<p>No findings recorded.</p>"

    rows = []

    for finding in report.findings:
        rows.append(
            f"""
```

<tr>
<td>{escape(str(finding.finding_id))}</td>
<td>{escape(str(finding.title))}</td>
<td>{escape(str(finding.severity))}</td>
<td>{escape(str(finding.confidence))}</td>
<td>{escape(str(finding.status))}</td>
<td>{escape(str(finding.validation_status))}</td>
<td>{escape(
    str(finding.security_requirement)
)}</td>
</tr>
"""
            )

```
    return f"""
```

<table>
<thead>
<tr>
<th>ID</th>
<th>Title</th>
<th>Severity</th>
<th>Confidence</th>
<th>Status</th>
<th>Validation</th>
<th>Requirement</th>
</tr>
</thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
"""

```
@staticmethod
def _render_remediation(
    report: SecurityReport,
) -> str:
    """Render remediation summary."""
    remediation = report.remediation

    return f"""
```

<div class="grid">
<div class="card">
<div class="label">Total</div>
<div class="value">
{escape(str(remediation.total))}
</div>
</div>
<div class="card">
<div class="label">Open</div>
<div class="value">
{escape(str(remediation.open))}
</div>
</div>
<div class="card">
<div class="label">In Progress</div>
<div class="value">
{escape(str(remediation.in_progress))}
</div>
</div>
<div class="card">
<div class="label">Resolved</div>
<div class="value">
{escape(str(remediation.resolved))}
</div>
</div>
<div class="card">
<div class="label">Verified</div>
<div class="value">
{escape(str(remediation.verified))}
</div>
</div>
</div>
"""

```
@staticmethod
def _render_regression(
    report: SecurityReport,
) -> str:
    """Render regression execution results."""
    regression = report.regression

    summary = f"""
```

<div class="grid">
<div class="card">
<div class="label">Suite</div>
<div class="value">
{escape(str(regression.suite_name))}
</div>
</div>
<div class="card">
<div class="label">Status</div>
<div class="value">
{escape(str(regression.status))}
</div>
</div>
<div class="card">
<div class="label">Total</div>
<div class="value">
{escape(str(regression.total))}
</div>
</div>
<div class="card">
<div class="label">Passed</div>
<div class="value">
{escape(str(regression.passed))}
</div>
</div>
<div class="card">
<div class="label">Failed</div>
<div class="value">
{escape(str(regression.failed))}
</div>
</div>
<div class="card">
<div class="label">Errors</div>
<div class="value">
{escape(str(regression.errors))}
</div>
</div>
<div class="card">
<div class="label">Skipped</div>
<div class="value">
{escape(str(regression.skipped))}
</div>
</div>
</div>
"""

```
    if not regression.tests:
        return (
            summary
            + "<p>No regression tests were executed.</p>"
        )

    rows = []

    for test in regression.tests:
        evidence = (
            test.evidence
            if test.evidence
            else {}
        )

        rows.append(
            f"""
```

<tr>
<td>{escape(str(test.test_id))}</td>
<td>{escape(str(test.status))}</td>
<td>{escape(str(test.expected))}</td>
<td>{escape(str(test.actual))}</td>
<td>{escape(str(test.message))}</td>
<td><pre>{escape(str(evidence))}</pre></td>
</tr>
"""
            )

```
    return summary + f"""
```

<table>
<thead>
<tr>
<th>Test ID</th>
<th>Status</th>
<th>Expected</th>
<th>Actual</th>
<th>Message</th>
<th>Evidence</th>
</tr>
</thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
"""

```
@staticmethod
def _render_policy(
    report: SecurityReport,
) -> str:
    """Render policy evaluation information."""
    policy = report.policy

    actions = policy.actions

    if actions:
        action_rows = []

        for action in actions:
            action_rows.append(
                f"""
```

<tr>
<td>{escape(str(action))}</td>
</tr>
"""
                )

```
        actions_html = f"""
```

<table>
<thead>
<tr>
<th>Policy Action</th>
</tr>
</thead>
<tbody>
{''.join(action_rows)}
</tbody>
</table>
"""
        else:
            actions_html = (
                "<p>No policy actions recorded.</p>"
            )

```
    return f"""
```

<p>
Policy:
<strong>
{escape(str(policy.policy_name))}
</strong>
</p>
{actions_html}
"""

```
@staticmethod
def _render_tool_errors(
    report: SecurityReport,
) -> str:
    """Render tool execution errors."""
    errors = report.policy.tool_errors

    if not errors:
        return "<p>No tool errors recorded.</p>"

    items = "".join(
        f"<li>{escape(str(error))}</li>"
        for error in errors
    )

    return f"<ul>{items}</ul>"
```
