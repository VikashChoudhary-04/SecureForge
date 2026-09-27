"""HTML report rendering for SecureForge."""

from **future** import annotations

from html import escape
from pathlib import Path
from typing import Any

from .models import SecurityReport

class SecurityHTMLReportRenderer:
"""Render a SecureForge security report as standalone HTML."""

```
def render(
    self,
    report: SecurityReport,
) -> str:
    """Render a complete standalone HTML report."""
    release = report.release
    scan = report.scan
    risk = report.risk
    policy = report.policy
    remediation = report.remediation
    regression = report.regression
    decision = report.decision

    findings_html = self._render_findings(
        report.findings
    )

    regression_html = self._render_regression(
        regression.tests
    )

    tool_errors_html = self._render_list(
        policy.tool_errors,
        empty_message="No tool errors.",
    )

    regression_failures_html = self._render_list(
        policy.regression_failures,
        empty_message="No regression failures.",
    )

    decision_class = escape(
        decision.status.lower()
    )

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
      margin: 0;
      padding: 0;
      background: #f4f6f8;
      color: #17202a;
    }}

```
header {{
  background: #17202a;
  color: #ffffff;
  padding: 32px;
}}

header h1 {{
  margin: 0 0 8px 0;
}}

header p {{
  margin: 4px 0;
}}

main {{
  max-width: 1200px;
  margin: 24px auto;
  padding: 0 20px 40px;
}}

section {{
  background: #ffffff;
  margin-bottom: 20px;
  padding: 24px;
  border-radius: 8px;
  box-shadow: 0 1px 4px rgba(0, 0, 0, 0.08);
}}

h2 {{
  margin-top: 0;
}}

table {{
  width: 100%;
  border-collapse: collapse;
}}

th,
td {{
  text-align: left;
  padding: 10px;
  border-bottom: 1px solid #dfe6e9;
  vertical-align: top;
}}

th {{
  background: #f4f6f8;
}}

.decision {{
  border-left: 6px solid #17202a;
}}

.decision.block {{
  border-left-color: #c0392b;
}}

.decision.review {{
  border-left-color: #d68910;
}}

.decision.pass {{
  border-left-color: #1e8449;
}}

.status {{
  font-size: 1.4rem;
  font-weight: bold;
  text-transform: uppercase;
}}

.severity-critical,
.severity-high {{
  font-weight: bold;
}}

.muted {{
  color: #566573;
}}

ul {{
  margin-top: 8px;
}}

code {{
  background: #f4f6f8;
  padding: 2px 5px;
  border-radius: 4px;
}}
```

  </style>
</head>
<body>
  <header>
    <h1>SecureForge Security Report</h1>
    <p><strong>Application:</strong> {escape(release.application)}</p>
    <p><strong>Release:</strong> {escape(release.release_id)}</p>
    <p><strong>Version:</strong> {escape(release.version)}</p>
    <p><strong>Environment:</strong> {escape(release.environment)}</p>
    <p><strong>Profile:</strong> {escape(release.profile)}</p>
  </header>

  <main>
    <section class="decision {decision_class}">
      <h2>Release Decision</h2>
      <p class="status">{escape(decision.status)}</p>
      <p>{escape(decision.reason)}</p>
      <p>
        <strong>Release allowed:</strong>
        {escape(str(decision.release_allowed))}
      </p>
    </section>

```
<section>
  <h2>Scan Summary</h2>
  <table>
    <tr>
      <th>Scan ID</th>
      <td>{escape(scan.scan_id)}</td>
    </tr>
    <tr>
      <th>Status</th>
      <td>{escape(scan.status)}</td>
    </tr>
    <tr>
      <th>Profile</th>
      <td>{escape(release.profile)}</td>
    </tr>
    <tr>
      <th>Integrations</th>
      <td>{escape(", ".join(scan.integrations))}</td>
    </tr>
  </table>
</section>

<section>
  <h2>Risk Summary</h2>
  <table>
    <tr>
      <th>Overall Score</th>
      <td>{escape(str(risk.overall_score))}</td>
    </tr>
    <tr>
      <th>Highest Severity</th>
      <td>{escape(risk.highest_severity)}</td>
    </tr>
    <tr>
      <th>Confirmed Critical</th>
      <td>{risk.confirmed_critical}</td>
    </tr>
    <tr>
      <th>Confirmed High</th>
      <td>{risk.confirmed_high}</td>
    </tr>
  </table>
</section>

<section>
  <h2>Findings</h2>
  {findings_html}
</section>

<section>
  <h2>Remediation</h2>
  <table>
    <tr>
      <th>Open Findings</th>
      <td>{remediation.open_findings}</td>
    </tr>
    <tr>
      <th>Remediated Findings</th>
      <td>{remediation.remediated_findings}</td>
    </tr>
    <tr>
      <th>Verified Findings</th>
      <td>{remediation.verified_findings}</td>
    </tr>
    <tr>
      <th>Pending Retests</th>
      <td>{remediation.pending_retests}</td>
    </tr>
  </table>
</section>

<section>
  <h2>Regression Testing</h2>
  {regression_html}
</section>

<section>
  <h2>Policy Evaluation</h2>
  <table>
    <tr>
      <th>Policy</th>
      <td>{escape(policy.policy_name)}</td>
    </tr>
    <tr>
      <th>Critical</th>
      <td>{escape(policy.critical_action)}</td>
    </tr>
    <tr>
      <th>High</th>
      <td>{escape(policy.high_action)}</td>
    </tr>
    <tr>
      <th>Medium</th>
      <td>{escape(policy.medium_action)}</td>
    </tr>
    <tr>
      <th>Low</th>
      <td>{escape(policy.low_action)}</td>
    </tr>
  </table>

  <h3>Tool Errors</h3>
  {tool_errors_html}

  <h3>Regression Failures</h3>
  {regression_failures_html}
</section>

<section>
  <p class="muted">
    Generated by SecureForge.
  </p>
</section>
```

  </main>
</body>
</html>
"""

```
def write_html(
    self,
    report: SecurityReport,
    path: str | Path,
) -> Path:
    """Render and write an HTML report."""
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

def _render_findings(
    self,
    findings: list[Any],
) -> str:
    """Render findings as an HTML table."""
    if not findings:
        return "<p>No findings.</p>"

    rows: list[str] = []

    for finding in findings:
        severity_class = (
            "severity-"
            + escape(
                finding.severity.lower()
            )
        )

        rows.append(
            f"""
            <tr>
              <td>{escape(finding.finding_id)}</td>
              <td>{escape(finding.title)}</td>
              <td class="{severity_class}">
                {escape(finding.severity)}
              </td>
              <td>{escape(finding.confidence)}</td>
              <td>{escape(finding.source)}</td>
              <td>
                {escape(finding.endpoint or "-")}
              </td>
              <td>
                {escape(
                    finding.security_requirement
                    or "-"
                )}
              </td>
            </tr>
            """
        )

    return f"""
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Title</th>
          <th>Severity</th>
          <th>Confidence</th>
          <th>Source</th>
          <th>Endpoint</th>
          <th>Requirement</th>
        </tr>
      </thead>
      <tbody>
        {"".join(rows)}
      </tbody>
    </table>
    """

@staticmethod
def _render_regression(
    tests: list[Any],
) -> str:
    """Render regression results as an HTML table."""
    if not tests:
        return "<p>No regression tests executed.</p>"

    rows: list[str] = []

    for test in tests:
        rows.append(
            f"""
            <tr>
              <td>{escape(test.test_id)}</td>
              <td>{escape(test.requirement)}</td>
              <td>{escape(test.status)}</td>
              <td>
                {escape(test.expected_result or "-")}
              </td>
              <td>
                {escape(test.actual_result or "-")}
              </td>
              <td>
                {escape(test.message or "-")}
              </td>
            </tr>
            """
        )

    return f"""
    <table>
      <thead>
        <tr>
          <th>Test ID</th>
          <th>Requirement</th>
          <th>Status</th>
          <th>Expected</th>
          <th>Actual</th>
          <th>Message</th>
        </tr>
      </thead>
      <tbody>
        {"".join(rows)}
      </tbody>
    </table>
    """

@staticmethod
def _render_list(
    values: list[str],
    *,
    empty_message: str,
) -> str:
    """Render a list of strings as HTML."""
    if not values:
        return (
            f"<p>{escape(empty_message)}</p>"
        )

    items = "".join(
        f"<li>{escape(value)}</li>"
        for value in values
    )

    return f"<ul>{items}</ul>"
```
