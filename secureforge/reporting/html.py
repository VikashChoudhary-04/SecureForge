"""HTML report rendering for SecureForge."""

from __future__ import annotations

from html import escape
from typing import Any

from .models import SecurityReport


class HTMLReportRenderer:
    """Render SecureForge security reports as HTML."""

    def render(
        self,
        report: SecurityReport,
    ) -> str:
        """Render a complete security report."""
        return f"""<!DOCTYPE html>
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

header {{
    background: #111827;
    color: white;
    padding: 24px 32px;
}}

main {{
    max-width: 1200px;
    margin: 0 auto;
    padding: 24px;
}}

section {{
    background: white;
    border-radius: 8px;
    margin-bottom: 20px;
    padding: 20px;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
}}

h1,
h2,
h3 {{
    margin-top: 0;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th,
td {{
    border: 1px solid #d1d5db;
    padding: 8px;
    text-align: left;
    vertical-align: top;
}}

th {{
    background: #f3f4f6;
}}

.status {{
    display: inline-block;
    padding: 6px 10px;
    border-radius: 4px;
    font-weight: bold;
}}

.pass {{
    background: #dcfce7;
    color: #166534;
}}

.block {{
    background: #fee2e2;
    color: #991b1b;
}}

.review {{
    background: #fef3c7;
    color: #92400e;
}}

.muted {{
    color: #6b7280;
}}

pre {{
    white-space: pre-wrap;
    word-break: break-word;
}}

.finding {{
    margin-bottom: 18px;
    border: 1px solid #d1d5db;
    border-radius: 6px;
    padding: 14px;
}}

.badge {{
    display: inline-block;
    margin-right: 6px;
    margin-bottom: 4px;
    padding: 3px 7px;
    border-radius: 3px;
    background: #e5e7eb;
}}

</style>
</head>
<body>
<header>
    <h1>SecureForge Security Report</h1>
    <p>
        {escape(report.release.application)}
        &mdash;
        {escape(report.release.version)}
    </p>
</header>

<main>
    {self._render_decision(report)}
    {self._render_release(report)}
    {self._render_scan(report)}
    {self._render_risk(report)}
    {self._render_policy(report)}
    {self._render_validation(report)}
    {self._render_validation_results(report)}
    {self._render_findings(report)}
    {self._render_remediation(report)}
    {self._render_regression(report)}
    {self._render_metadata(report)}
</main>
</body>
</html>
"""

    def _render_decision(
        self,
        report: SecurityReport,
    ) -> str:
        """Render the final release decision."""
        status_class = (
            "pass"
            if report.decision.allowed
            else "block"
        )

        status_text = (
            "PASS"
            if report.decision.allowed
            else "BLOCK"
        )

        return f"""
<section>
    <h2>Release Decision</h2>
    <p>
        <span class="status {status_class}">
            {status_text}
        </span>
    </p>
    <p>
        <strong>Status:</strong>
        {escape(report.decision.status)}
    </p>
    <p>
        <strong>Reason:</strong>
        {escape(report.decision.reason)}
    </p>
</section>
"""

    def _render_release(
        self,
        report: SecurityReport,
    ) -> str:
        """Render release metadata."""
        commit_sha = (
            escape(report.release.commit_sha)
            if report.release.commit_sha
            else "Not provided"
        )

        return f"""
<section>
    <h2>Release</h2>
    <table>
        <tr>
            <th>Scan ID</th>
            <td>{escape(report.release.scan_id)}</td>
        </tr>
        <tr>
            <th>Application</th>
            <td>{escape(report.release.application)}</td>
        </tr>
        <tr>
            <th>Version</th>
            <td>{escape(report.release.version)}</td>
        </tr>
        <tr>
            <th>Commit SHA</th>
            <td>{commit_sha}</td>
        </tr>
        <tr>
            <th>Environment</th>
            <td>{escape(report.release.environment)}</td>
        </tr>
    </table>
</section>
"""

    def _render_scan(
        self,
        report: SecurityReport,
    ) -> str:
        """Render scan metadata."""
        tools = (
            ", ".join(
                escape(tool)
                for tool in report.scan.tools
            )
            if report.scan.tools
            else "None"
        )

        errors = (
            "<ul>"
            + "".join(
                f"<li>{escape(error)}</li>"
                for error in report.scan.tool_errors
            )
            + "</ul>"
            if report.scan.tool_errors
            else "<p class=\"muted\">None</p>"
        )

        return f"""
<section>
    <h2>Scan</h2>
    <table>
        <tr>
            <th>Profile</th>
            <td>{escape(report.scan.profile)}</td>
        </tr>
        <tr>
            <th>Started</th>
            <td>{escape(report.scan.started_at)}</td>
        </tr>
        <tr>
            <th>Completed</th>
            <td>{escape(report.scan.completed_at)}</td>
        </tr>
        <tr>
            <th>Tools</th>
            <td>{tools}</td>
        </tr>
    </table>

    <h3>Tool Errors</h3>
    {errors}
</section>
"""

    def _render_risk(
        self,
        report: SecurityReport,
    ) -> str:
        """Render risk information."""
        factors = (
            "<table>"
            "<tr>"
            "<th>Factor</th>"
            "<th>Value</th>"
            "</tr>"
            + "".join(
                self._render_dict_row(factor)
                for factor in report.risk.factors
            )
            + "</table>"
            if report.risk.factors
            else "<p class=\"muted\">No risk factors.</p>"
        )

        return f"""
<section>
    <h2>Risk Assessment</h2>
    <p>
        <strong>Score:</strong>
        {report.risk.overall_score}
    </p>
    <p>
        <strong>Severity:</strong>
        {escape(report.risk.overall_severity)}
    </p>
    <p>
        <strong>Blocked:</strong>
        {report.risk.blocked}
    </p>
    {factors}
</section>
"""

    def _render_policy(
        self,
        report: SecurityReport,
    ) -> str:
        """Render policy evaluation."""
        status_class = (
            "pass"
            if report.policy.allowed
            else "block"
        )

        return f"""
<section>
    <h2>Policy Evaluation</h2>
    <p>
        <span class="status {status_class}">
            {escape(report.policy.status)}
        </span>
    </p>
    <p>
        <strong>Reason:</strong>
        {escape(report.policy.reason)}
    </p>
    <p>
        <strong>Actions:</strong>
        {len(report.policy.actions)}
    </p>
    <p>
        <strong>Exceptions:</strong>
        {len(report.policy.exceptions)}
    </p>
</section>
"""

    def _render_validation(
        self,
        report: SecurityReport,
    ) -> str:
        """Render validation summary and gate."""
        if report.validation is None:
            return """
<section>
    <h2>Security Validation</h2>
    <p class="muted">
        Validation was not executed for this scan.
    </p>
</section>
"""

        gate_html = ""

        if report.validation_gate is not None:
            gate_class = (
                "pass"
                if report.validation_gate.allowed
                else "block"
            )

            gate_html = f"""
<h3>Validation Gate</h3>
<p>
    <span class="status {gate_class}">
        {escape(report.validation_gate.status)}
    </span>
</p>
<p>
    <strong>Reason:</strong>
    {escape(report.validation_gate.reason)}
</p>
<p>
    <strong>Requires attention:</strong>
    {report.validation_gate.requires_attention}
</p>
"""

        return f"""
<section>
    <h2>Security Validation</h2>

    <table>
        <tr>
            <th>Total</th>
            <td>{report.validation.total}</td>
        </tr>
        <tr>
            <th>Confirmed</th>
            <td>{report.validation.confirmed}</td>
        </tr>
        <tr>
            <th>Rejected</th>
            <td>{report.validation.rejected}</td>
        </tr>
        <tr>
            <th>Inconclusive</th>
            <td>{report.validation.inconclusive}</td>
        </tr>
        <tr>
            <th>Errors</th>
            <td>{report.validation.errors}</td>
        </tr>
        <tr>
            <th>Remediated</th>
            <td>{report.validation.remediated}</td>
        </tr>
        <tr>
            <th>All Validated</th>
            <td>{report.validation.all_validated}</td>
        </tr>
    </table>

    {gate_html}
</section>
"""

    def _render_validation_results(
        self,
        report: SecurityReport,
    ) -> str:
        """Render individual validation results."""
        if not report.validation_results:
            return ""

        rows = []

        for result in report.validation_results:
            outcome_class = (
                "pass"
                if result.rejected
                else "block"
                if result.confirmed or result.failed
                else "review"
            )

            rows.append(
                f"""
<tr>
    <td>{escape(result.finding_id)}</td>
    <td>
        <span class="status {outcome_class}">
            {escape(result.outcome)}
        </span>
    </td>
    <td>{escape(result.validator)}</td>
    <td>{escape(result.message)}</td>
    <td>{result.remediation_verified}</td>
</tr>
"""
            )

        return f"""
<section>
    <h2>Validation Results</h2>
    <table>
        <tr>
            <th>Finding</th>
            <th>Outcome</th>
            <th>Validator</th>
            <th>Message</th>
            <th>Remediation Verified</th>
        </tr>
        {"".join(rows)}
    </table>
</section>
"""

    def _render_findings(
        self,
        report: SecurityReport,
    ) -> str:
        """Render security findings."""
        if not report.findings:
            return """
<section>
    <h2>Findings</h2>
    <p class="muted">
        No findings were produced.
    </p>
</section>
"""

        content = []

        for finding in report.findings:
            correlation = (
                ", ".join(
                    escape(item)
                    for item in finding.correlation_ids
                )
                if finding.correlation_ids
                else "None"
            )

            content.append(
                f"""
<div class="finding">
    <h3>
        {escape(finding.finding_id)}
        &mdash;
        {escape(finding.title)}
    </h3>

    <p>
        <span class="badge">
            Severity: {escape(finding.severity)}
        </span>
        <span class="badge">
            Confidence: {escape(finding.confidence)}
        </span>
        <span class="badge">
            Status: {escape(finding.status)}
        </span>
        <span class="badge">
            Validation: {escape(finding.validation_status)}
        </span>
    </p>

    <p>
        <strong>Source:</strong>
        {escape(finding.source)}
    </p>

    <p>
        <strong>Asset:</strong>
        {escape(finding.asset)}
    </p>

    <p>
        <strong>Endpoint:</strong>
        {escape(finding.endpoint or "Not provided")}
    </p>

    <p>
        <strong>Parameter:</strong>
        {escape(finding.parameter or "Not provided")}
    </p>

    <p>
        <strong>CWE:</strong>
        {escape(finding.cwe or "Not mapped")}
    </p>

    <p>
        <strong>OWASP:</strong>
        {escape(
            finding.owasp_mapping
            or "Not mapped"
        )}
    </p>

    <p>
        <strong>Security Requirement:</strong>
        {escape(
            finding.security_requirement
            or "Not mapped"
        )}
    </p>

    <p>
        <strong>Description:</strong>
        {escape(finding.description)}
    </p>

    <p>
        <strong>Impact:</strong>
        {escape(finding.impact)}
    </p>

    <p>
        <strong>Remediation:</strong>
        {escape(finding.remediation)}
    </p>

    <p>
        <strong>Correlation IDs:</strong>
        {correlation}
    </p>

    <p>
        <strong>Regression Test:</strong>
        {escape(
            finding.regression_test
            or "None"
        )}
    </p>
</div>
"""
            )

        return f"""
<section>
    <h2>Findings</h2>
    {"".join(content)}
</section>
"""

    def _render_remediation(
        self,
        report: SecurityReport,
    ) -> str:
        """Render remediation summary."""
        items = report.remediation.findings

        content = (
            "<ul>"
            + "".join(
                f"""
<li>
    <strong>
        {escape(str(item.get("finding_id", "")))}
    </strong>
    &mdash;
    {escape(str(item.get("status", "")))}
    &mdash;
    {escape(str(item.get("remediation", "")))}
</li>
"""
                for item in items
            )
            + "</ul>"
            if items
            else "<p class=\"muted\">No remediation items.</p>"
        )

        return f"""
<section>
    <h2>Remediation</h2>
    <p>
        <strong>Total:</strong>
        {report.remediation.total}
    </p>
    <p>
        <strong>Open:</strong>
        {report.remediation.open_count}
    </p>
    <p>
        <strong>Remediated:</strong>
        {report.remediation.remediated_count}
    </p>
    {content}
</section>
"""

    def _render_regression(
        self,
        report: SecurityReport,
    ) -> str:
        """Render regression testing information."""
        if report.regression is None:
            return """
<section>
    <h2>Regression Testing</h2>
    <p class="muted">
        Regression testing was not executed.
    </p>
</section>
"""

        gate_html = ""

        if report.regression_gate is not None:
            gate_class = (
                "pass"
                if report.regression_gate.allowed
                else "block"
            )

            gate_html = f"""
<h3>Regression Gate</h3>
<p>
    <span class="status {gate_class}">
        {escape(report.regression_gate.status)}
    </span>
</p>
<p>
    <strong>Reason:</strong>
    {escape(report.regression_gate.reason)}
</p>
"""

        rows = "".join(
            f"""
<tr>
    <td>{escape(test.test_id)}</td>
    <td>{escape(test.status)}</td>
    <td>{escape(test.message)}</td>
</tr>
"""
            for test in report.regression.tests
        )

        return f"""
<section>
    <h2>Regression Testing</h2>

    <table>
        <tr>
            <th>Total</th>
            <td>{report.regression.total}</td>
        </tr>
        <tr>
            <th>Passed</th>
            <td>{report.regression.passed}</td>
        </tr>
        <tr>
            <th>Failed</th>
            <td>{report.regression.failed}</td>
        </tr>
        <tr>
            <th>Errored</th>
            <td>{report.regression.errored}</td>
        </tr>
        <tr>
            <th>Skipped</th>
            <td>{report.regression.skipped}</td>
        </tr>
    </table>

    {gate_html}

    <h3>Tests</h3>

    <table>
        <tr>
            <th>Test ID</th>
            <th>Status</th>
            <th>Message</th>
        </tr>
        {rows}
    </table>
</section>
"""

    def _render_metadata(
        self,
        report: SecurityReport,
    ) -> str:
        """Render report generation metadata."""
        return f"""
<section>
    <h2>Report Metadata</h2>
    <p>
        <strong>Generated:</strong>
        {escape(report.generated_at)}
    </p>
</section>
"""

    @staticmethod
    def _render_dict_row(
        value: dict[str, Any],
    ) -> str:
        """Render a dictionary as an HTML table row."""
        if not value:
            return "<tr><td colspan=\"2\">None</td></tr>"

        items = []

        for key, item in value.items():
            items.append(
                f"""
<tr>
    <th>{escape(str(key))}</th>
    <td>{escape(str(item))}</td>
</tr>
"""
            )

        return "".join(items)


__all__ = [
    "HTMLReportRenderer",
]
